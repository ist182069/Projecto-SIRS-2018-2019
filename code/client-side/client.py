# CLIENT
try:
    import socket
    import ssl
    import argparse
    import os
    import sys
    import errno
    import time
    import datetime
    import json
    import subprocess
    import hashlib
    import argcomplete
    # our custom modules
    sys.path.insert(0, "utils" + os.sep + "aux-py-modules")
    import AESCipher
except ImportError:
    raise ImportError("You need to do 'pip install -r requirements.txt' to be able to use this program.")

# PRELIMINARY NOTE: read the README.txt for informations about how to run this file
# READING:
# [!]: error information
# [+]: normal information
# [x]: output information

OK_MSG = "OK"

# =====================
#     CLI OPTIONS
# =====================

op = argparse.ArgumentParser(description='SIRS Project client interface')
op.add_argument('-r', '--register', help='register command: requires username', dest='register', default="")     # need to provide new cliente name
op.add_argument('-l', '--login', help='login command: requires username', dest='login', default="")     # need to provide client name
op.add_argument('-s', '--synchronize-individual', help='synchronize file or directory from default directory "myfiles": requires path', dest='synchronize', default="") # (flow from client to server)
op.add_argument('-S', '--synchronize-all-individual', help='recursively synchronize all individual files from default directory', action='store_true', dest='synchronizeallindiv') # (flow from client to server)
op.add_argument('-f', '--fetch-individual', help='fetch file or directory into default directory: requires path', dest='fetch', default="") # (flow from server to client)
op.add_argument('-F', '--fetch-all-individual', help='recursively fetch all individual files into default directory', action='store_true', dest='fetchallindiv') # (flow from server to client)
op.add_argument('-lfiles','--list-files', help='get a list of my currently saved files in the server (individual and shared)', action='store_true', dest='listmyfiles')
op.add_argument('-lusers','--list-all-users', help='get a list of other server users', action='store_true', dest='listallusers')
op.add_argument('-share', '--share', help='share a file or directory with a list of existent users (from that point on, work on it in the "mysharedfiles" folder): requires path', dest='share', default='') # (flow from client to server)
op.add_argument('-fshared', '--fetch-shared', help='fetch shared files with a list of existent users into the "mysharedfiles" folder: requires path', dest='fetchshared', default='') # (flow from server to client)
op.add_argument('-sshared', '--synchronize-shared', help='synchronize shared files with a list of existent users from the "mysharedfiles" folder: requires path', dest='synchronizeshared', default='') # (flow from client to server)
op.add_argument('-lbackups', '--list-backups', help='lists backups the client has on the server',  action='store_true', dest='listmybackups') # revert specific file (flow from server to client)
op.add_argument('-revindiv', '--revert-individual', help='fetches a backup of an individual file',  action='store_true', dest='revert') # revert specific file (flow from server to client)
op.add_argument('-revshared', '--revert-shared', help='fetches a backup of a shared file',  action='store_true', dest='revertshared') # revert specific file (flow from server to client)
op.add_argument('-delindiv', '--delete-individual', help='deletes an individual file from the server (backups are maintained)', dest='deleteindividual', default="")
argcomplete.autocomplete(op)
args = op.parse_args()

# HMAC w/ sha256 (not used anymore now)
def hmac_sha256(content, secret_key):
    # more info: https://en.wikipedia.org/wiki/HMAC
    # slides: HMAC(m,k) = hash(k^opad + hash(k^ipad+m))
    outter_padding_str = "".join([chr(x^0x5C) for x in range(256)])
    inner_padding_str = "".join([chr(x^0x36) for x in range(256)])
    outer_key_padding = hashlib.sha256()
    inner_key_padding = hashlib.sha256()
    # padding key with 0's
    secret_key = secret_key + '\x00' * (inner_key_padding.block_size - len(secret_key))

    outer_key_padding.update(secret_key.translate(outter_padding_str))
    inner_key_padding.update(secret_key.translate(inner_padding_str))
    inner_key_padding.update(content)
    outer_key_padding.update(inner_key_padding.digest())

    hmac = outer_key_padding.hexdigest()
    return hmac

def encrypt_key(aeskey_bytecode, pubkey_path):
    script_path = "." + os.sep + "utils" + os.sep + "CLIENT_ENCRYPT_SYMKEY.sh"
    proc = subprocess.Popen([script_path,aeskey_bytecode, pubkey_path], stdout=subprocess.PIPE)
    encrypted_aeskey_bytecode = proc.stdout.read().encode("hex")
    return encrypted_aeskey_bytecode

def decrypt_key(encrypted_aeskey_bytecode, privkey_path):
    script_path = "." + os.sep + "utils" + os.sep + "CLIENT_DECRYPT_SYMKEY.sh"
    encrypted_aeskey = encrypted_aeskey_bytecode.decode("hex")
    tmp_encryptedkeyfile = "symkey.bin.encrypted"
    f = open(tmp_encryptedkeyfile, "w")
    f.write(encrypted_aeskey)
    f.close()
    proc = subprocess.Popen([script_path,tmp_encryptedkeyfile, privkey_path], stdout=subprocess.PIPE)
    decrypted_aeskey_bytecode = proc.stdout.read()[:-1]
    return decrypted_aeskey_bytecode

def encrypt_file(filepath, aeskey_bytecode, iv_bytecode, client_name):
    aeskey = bytearray.fromhex(aeskey_bytecode)
    aesiv = bytearray.fromhex(iv_bytecode)
    aeskeybuffer = buffer(aeskey)
    aesivbuffer = buffer(aesiv)
    aesCipher = AESCipher.AESCipher(aeskeybuffer)
    f = open(filepath)
    filecontent = f.read()
    f.close()
    filecontent_clientname = filecontent + "\n" + client_name
    ciphered_text = aesCipher.encrypt(filecontent_clientname, aesivbuffer)
    return ciphered_text

def sign_file(ciphertext_filepath, privkey_path):
    cmd = "." + os.sep + "utils" + os.sep + "CLIENT_SIGN_DOCUMENT.sh " + ciphertext_filepath + " " + privkey_path
    subprocess.check_call(cmd.split(), stdout=open(os.devnull), stderr=subprocess.STDOUT)
    return ciphertext_filepath + ".sig"

def decrypt_filecontent(encrypted_filecontent, aeskey_bytecode):
    aeskey = bytearray.fromhex(aeskey_bytecode)
    aeskeybuffer = buffer(aeskey)
    file_bcbuffer = buffer(encrypted_filecontent)
    aesCipher = AESCipher.AESCipher(aeskeybuffer)
    deciphered_text = aesCipher.decrypt(file_bcbuffer)
    return deciphered_text

def verify_digital_signature(pubkey_path,sig_filepath,cryptogram_filepath):
    cmd = "openssl dgst -sha256 -verify " + pubkey_path + " -signature " + sig_filepath + " " + cryptogram_filepath
    proc = subprocess.Popen(cmd.split(), stdout=subprocess.PIPE)
    sig_verification = proc.stdout.read()
    return sig_verification=="Verified OK\n"

def reconstruct_client_files(file_structure, clientside_dirname, client_name, sharedfiles_flag=False):
    privkey_path = mycert_dir + os.sep + client_name + ".key"
    for clientside_directory in file_structure:
        files = file_structure[clientside_directory]
        if sandbox_escaped(clientside_directory, clientside_dirname):
            exit()
        mkdir_p(clientside_directory)
        for filename in files:
            if filename.endswith(".key.encrypted") or filename.endswith(".key.encrypted." + client_name) or filename.endswith(".sig"):
                pass
            else:
                filename_noext = filename.rsplit(".encrypted", 1)[0]
                clientside_filepath = clientside_directory + os.sep + filename_noext
                if sandbox_escaped(clientside_filepath, clientside_dirname):
                    exit()
                encrypted_filecontent_bytecode = files[filename][0]
                key_entry = filename_noext + ".key.encrypted" if not sharedfiles_flag else filename_noext + ".key.encrypted." + client_name
                sig_entry = filename_noext + ".sig"
                encrypted_aeskey_bytecode = files[key_entry][0]
                signature_bytecode = files[sig_entry][0]

                aeskey_bytecode = decrypt_key(encrypted_aeskey_bytecode, privkey_path)
                encrypted_filecontent = encrypted_filecontent_bytecode.decode("hex")
                decrypted_filecontent = decrypt_filecontent(encrypted_filecontent, aeskey_bytecode)
                decrypted_filecontent_split = decrypted_filecontent.rsplit("\n", 1)
                try:
                    relevant_decipheredtext = decrypted_filecontent_split[0]
                    lastmodifier_clientname = decrypted_filecontent_split[1]
                except IndexError:
                    print "[!][" + now() + "] No last line. This must mean the file you're trying to fetch has been illicitly modified. Aborting..."
                    exit()

                # already exists in the directory in the case of individual_files
                lastmodifier_pubkey_path = mycert_dir + os.sep + lastmodifier_clientname + ".pubkey" if not sharedfiles_flag \
                                            else shareuser_certs_dir + os.sep + lastmodifier_clientname + ".pubkey"
                signature = signature_bytecode.decode("hex")
                tmp_sig_filepath = "tmp_" + sig_entry
                f = open(tmp_sig_filepath, "w")
                f.write(signature)
                f.close()
                tmp_cryptogram_filepath = "tmp_" + filename
                f = open(tmp_cryptogram_filepath, "w")
                f.write(encrypted_filecontent)
                f.close()
                sig_verified = verify_digital_signature(lastmodifier_pubkey_path, tmp_sig_filepath, tmp_cryptogram_filepath)
                os.remove(tmp_sig_filepath)
                os.remove(tmp_cryptogram_filepath)
                if not sig_verified:
                    print "[!][" + now() + "] Ciphered-file signature not verified: file \"%s\" wasn't signed by %s, which was alledgedly the last signer of the document" \
                        %(tmp_cryptogram_filepath, lastmodifier_clientname)
                    exit()
                f = open(clientside_filepath, "w")
                f.write(relevant_decipheredtext)
                f.close()
    return True

def read_in_chunks(conn):
    data_len = int(conn.read())
    chunk_len = min(data_len, 16384)   # limit size before waiting
    data_repr = ""
    i=chunk_len
    while i<=data_len:
        data_repr += conn.recv(chunk_len)
        i += chunk_len
    if data_len%chunk_len!=0:
        data_repr += conn.recv(data_len%16384)
    data = json.loads(data_repr)
    return conn, data

def locally_generate_symkey():
    script_path = "." + os.sep + "utils" + os.sep + "CLIENT_GEN_SYMKEY.sh"
    proc = subprocess.Popen([script_path], stdout=subprocess.PIPE)
    subpro_output = proc.stdout.read()
    split_output = subpro_output.splitlines()
    aeskey_bytecode = split_output[0].split('=')[1]
    iv_bytecode = split_output[1].split('=')[1]
    return aeskey_bytecode, iv_bytecode

def path_traversal_verified(suspect_filepath, highestlevel_dirname):
    if os.path.commonprefix((os.path.realpath(suspect_filepath),os.path.abspath(highestlevel_dirname))) != os.path.abspath(highestlevel_dirname):
        return False
    return True

def sandbox_escaped(currentside_filepath, currentside_dirname):
    if not path_traversal_verified(currentside_filepath, currentside_dirname):
        print "[!][" + now() + "] An error occurred, the server sent us an invalid file structure. Aborting..."
        return True
    return False

def get_digital_signature(encrypted_filecontent, privkey_path):
    tmp_ciphertext_filepath = "tmp_ciphered"
    f = open(tmp_ciphertext_filepath, "w")
    f.write(encrypted_filecontent)
    f.close()
    sig_filepath = sign_file(tmp_ciphertext_filepath, privkey_path)
    f = open(sig_filepath)
    signature = f.read()
    f.close()
    os.remove(tmp_ciphertext_filepath)
    os.remove(sig_filepath)
    return signature

# slides: A ---> B: {{"Alice", plaintext}B,#plaintext}a
def file_prepare(currentside_filepath, filebasename, client_name, file_structure):
    privkey_path = mycert_dir + os.sep + client_name + ".key"
    pubkey_path = mycert_dir + os.sep + client_name + ".pubkey"
    aeskey_bytecode, iv_bytecode = locally_generate_symkey()
    encrypted_filecontent_bytecode = encrypt_file(currentside_filepath, aeskey_bytecode, iv_bytecode, client_name)
    encrypted_aeskey_bytecode = encrypt_key(aeskey_bytecode, pubkey_path)
    encrypted_filecontent = encrypted_filecontent_bytecode.decode("hex")
    signature = get_digital_signature(encrypted_filecontent, privkey_path)
    signature_bytecode = signature.encode("hex")
    file_structure[os.path.dirname(currentside_filepath)][filebasename] = \
        [encrypted_filecontent_bytecode, encrypted_aeskey_bytecode, signature_bytecode, os.path.getmtime(currentside_filepath)]
    return file_structure

# slides: A ---> B: {{"Alice", plaintext}B,#plaintext}a
def sharedfile_prepare(currentside_filepath, filebasename, user_certs, client_name, sharedfile_structure):
    privkey_path = mycert_dir + os.sep + client_name + ".key"
    aeskey_bytecode, iv_bytecode = locally_generate_symkey()
    encrypted_filecontent_bytecode = encrypt_file(currentside_filepath, aeskey_bytecode, iv_bytecode, client_name)
    encrypted_filecontent = encrypted_filecontent_bytecode.decode("hex")
    signature = get_digital_signature(encrypted_filecontent, privkey_path)
    signature_bytecode = signature.encode("hex")
    sharedfile_structure[os.path.dirname(currentside_filepath)][filebasename] = [encrypted_filecontent_bytecode, signature_bytecode, os.path.getmtime(currentside_filepath)]
    for user in user_certs:
        cert = user_certs[user]
        shareuser_cert_path = shareuser_certs_dir + os.sep + user + ".crt"
        f = open(shareuser_cert_path, "w")
        f.write(cert)
        f.close()
        verify_received_certificate(shareuser_cert_path)
        # getting public keys from received certificates
        shareuser_pubkey_path = shareuser_certs_dir + os.sep + user + ".pubkey"
        cmd = "openssl x509 -inform pem -in " + shareuser_cert_path + " -pubkey -out " + shareuser_pubkey_path
        subprocess.check_call(cmd.split(), stdout=open(os.devnull), stderr=subprocess.STDOUT)
        encrypted_aeskey_bytecode = encrypt_key(aeskey_bytecode, shareuser_pubkey_path)
        sharedfile_structure[os.path.dirname(currentside_filepath)][filebasename].append([user, encrypted_aeskey_bytecode])
    return sharedfile_structure

def filestructure_prepare(currentside_dirname, pubkey_path, client_name, file_structure, user_certs=False, sharedfiles_flag=False):
    for filebasename in os.listdir(currentside_dirname):
        currentside_filepath = currentside_dirname + os.sep + filebasename
        try:
            remoteside_filepath = currentside_filepath.split(currentside_dirname, 1)[1].lstrip(os.sep)
        except IndexError:
            print "[!][" + now() + "] You didn't specify a path within the \"myfiles\" directory, aborting..."
            exit()
        if os.path.isdir(currentside_filepath):
            file_structure[currentside_filepath] = dict()
            file_structure = filestructure_prepare(currentside_filepath, pubkey_path, client_name, file_structure, user_certs, sharedfiles_flag)
    for filebasename in os.listdir(currentside_dirname):
        currentside_filepath = currentside_dirname + os.sep + filebasename
        remoteside_filepath = currentside_filepath.split(currentside_dirname, 1)[1].lstrip(os.sep)
        if not os.path.isdir(currentside_filepath) and not sharedfiles_flag:
            file_structure = file_prepare(currentside_filepath, filebasename, client_name, file_structure)
        elif not os.path.isdir(currentside_filepath) and sharedfiles_flag:
            file_structure = sharedfile_prepare(currentside_filepath, filebasename, user_certs, client_name, file_structure)
    return file_structure

def sanitize_clientname(client_name):
    removed_str_list = [" ", "\"", "'", "\\", "/", ".", "-", ";", "\n", "=", ",", "*", "@", "%", "$", "!"]
    for character in removed_str_list:
        client_name = client_name.replace(character,"")
    return client_name

def modify_client_csr_config(client_csr_config, client_name):
    client_csr_config = client_csr_config.replace("O = SIRS Client", "O = " + client_name)
    client_csr_config = client_csr_config.replace("CN = *.sirs-client.org", "CN = *." + client_name + ".org")
    client_csr_config = client_csr_config.replace("DNS.1 = *.sirs-client.org", "DNS.1 = *." + client_name + ".org")
    client_csr_config = client_csr_config.replace("DNS.2 = *.sirs-client.net", "DNS.2 = *." + client_name + ".net")
    client_csr_config = client_csr_config.replace("DNS.3 = *.sirs-client.in", "DNS.3 = *." + client_name + ".in")
    client_csr_config = client_csr_config.replace("DNS.4 = sirs-client.org", "DNS.4 = " + client_name + ".org")
    client_csr_config = client_csr_config.replace("DNS.5 = sirs-client.net", "DNS.5 = " + client_name + ".net")
    client_csr_config = client_csr_config.replace("DNS.6 = sirs-client.in", "DNS.6 = " + client_name + ".in")
    return client_csr_config

def now():
    return datetime.datetime.fromtimestamp(time.time()).strftime('%Y-%m-%d %H:%M:%S')

def mkdir_p(path):
    try:
        os.makedirs(path)
    except OSError as exc:  # Python >2.5
        if exc.errno == errno.EEXIST and os.path.isdir(path):
            pass
        else:
            raise

def locally_generate_csr(client_name, script_dir):
    print "[+][" + now() + "] Generating my certificate signing request..."
    client_csr_config_filename = script_dir + os.sep + "conf_client" + os.sep + "client_crt_config.conf"
    # MODIFY CONFIG FILE BASED ON CLIENT NAME
    f = open(client_csr_config_filename, "r")
    original_client_csr_config = f.read()
    f.close()
    client_csr_config = modify_client_csr_config(original_client_csr_config, client_name)
    f = open(client_csr_config_filename, "w")
    f.write(client_csr_config)
    f.close()

    # GENERATE CSR BASED ON CONFIG FILE
    cmd = "." + os.sep + script_dir + os.sep + "CLIENT_CERTS_KEYPAIRS.sh " + script_dir
    subprocess.check_call(cmd.split(), stdout=open(os.devnull), stderr=subprocess.STDOUT)
    os.rename(mycert_dir + os.sep + "sirs-client.key", mycert_dir + os.sep + client_name + ".key")
    os.rename(mycert_dir + os.sep + "sirs-client.pubkey", mycert_dir + os.sep + client_name + ".pubkey")
    mycert_path = mycert_dir + os.sep + "sirs-client.csr"
    f = open(mycert_path, "r")
    cert_sign_request = f.read()
    f.close()
    # RESTORE CLIENT CONFIG FILE
    f = open(client_csr_config_filename, "w")
    f.write(original_client_csr_config)
    f.close()
    return cert_sign_request

def list_my_files(mutual_conn, client_name, tag="ALL"):
    mutual_conn.send("LIST-MY-FILES")
    print "[+][" + now() + "] Client-Server: 'LIST-MY-FILES'"
    print "[x] The output is of form <client-side directory, last-time synchronized>"
    mutual_conn, individualfile_structure = read_in_chunks(mutual_conn)
    mutual_conn, sharedfile_structure_list = read_in_chunks(mutual_conn)
    if tag=="ALL" or tag=="Individual-Only":
        mutual_conn = list_individual_files(mutual_conn, individualfile_structure)
    if tag=="ALL" or tag=="Shared-Only":
        mutual_conn = list_shared_files(mutual_conn, sharedfile_structure_list, client_name)
    return mutual_conn

def list_individual_files(mutual_conn, individualfile_structure):
    print "[x] Individual files saved server-side:"
    for clientside_directory in individualfile_structure:
        for filebasename in individualfile_structure[clientside_directory]:
            if filebasename.endswith(".key.encrypted"):
                continue
            elif filebasename.endswith(".sig"):
                continue
            elif filebasename.endswith(".encrypted"):
                print clientside_directory + os.sep + filebasename.rsplit(".",1)[0] + " : " + individualfile_structure[clientside_directory][filebasename]
            else:
                print "[!][" + now() + "] Something went wrong. Aborting..."
                exit()
    return mutual_conn

def list_shared_files(mutual_conn, sharedfile_structure_list, client_name):
    print "[x] Shared files saved server-side:"
    for sharedfile_structure in sharedfile_structure_list:
        for clientside_directory in sharedfile_structure:
            for filebasename in sharedfile_structure[clientside_directory]:
                if filebasename.endswith(".key.encrypted." + client_name):
                    continue
                elif filebasename.endswith(".encrypted"):
                    print clientside_directory + os.sep + filebasename.rsplit(".",1)[0] + " : " + sharedfile_structure[clientside_directory][filebasename]
                else:
                    print "[!][" + now() + "] Something went wrong. Aborting..."
                    exit()
    return mutual_conn

def verify_pre_conditions():
    client_name = ""
    args_list = [args.register!="", args.login!="", args.synchronize!="", args.synchronizeallindiv, args.fetch!="", \
                args.fetchallindiv, args.listmyfiles, args.listallusers, args.share!="", args.fetchshared!="", args.synchronizeshared!="",\
                args.listmybackups, args.revert, args.revertshared, args.deleteindividual!=""]

    if True not in args_list:
        print "[!][" + now() + "] You need to choose an option."
        op.print_help()
        exit()
    
    if args.register and True in args_list[1:]:
        print "[!][" + now() + "] You need to choose only ONE option alongside the 'register' option."
        exit()

    if args.synchronize or args.synchronizeallindiv or args.fetch or args.fetchallindiv or args.share or args.fetchshared or args.synchronizeshared:
        if args_list[2:].count(True)!=1:
            print "[!][" + now() + "] You can only synchronize, synchronize individual files, fetch, fetch individual files, list your files," + \
                        " list all users, share, fetch shared files or synchronize shared files, one action at a time." 
            exit()

    if not args.login and True in args_list[2:]:
        print "[!][" + now() + "] You can only perform the specified action if you authenticate yourself first. Please specify option 'login'." 
        exit()

    if args.login and True not in (args_list[:1]+args_list[2:]):
        print "[!][" + now() + "] Please have in mind that when you authenticate yourself to the server you should be performing an action." + \
        " Your login state is not persistent, i.e., you have to authenticate yourself (login) everytime you want to perform an action that requires it." 
        exit()

    if args.register:
        client_name = args.register
    elif args.login:
        client_name = args.login

    if not client_name:
    	print "[!][" + now() + "] Error, you didn't specify your client name with the register/login option."
        exit()

    return client_name

def create_file_structure(clientside_path, client_name):
    pubkey_path = mycert_dir + os.sep + client_name + ".pubkey"
    filebasename = os.path.basename(clientside_path)
    file_structure = dict()
    if os.path.isfile(clientside_path):
        clientside_directory = os.path.dirname(clientside_path)
        file_structure[clientside_directory] = dict()     # current dir
        file_structure = file_prepare(clientside_path, filebasename, client_name, file_structure)
    elif os.path.isdir(clientside_path):
        file_structure[clientside_path] = dict()     # current dir
        file_structure = filestructure_prepare(clientside_path, pubkey_path, client_name, file_structure)
    else:
        print "[!][" + now() + "] You are trying to synchronize a non-existent file or directory. Aborting..."
        exit()
    return file_structure

def send_in_chunks(conn, data):
    data_repr = json.dumps(data)
    data_repr_len = len(data_repr)
    conn.send(str(data_repr_len))
    conn.send(data_repr)
    return conn

def verify_received_certificate(cert_path):
    cmd = "openssl verify -verbose -CAfile " + clientside_certificates_trustanchor_path + " " + cert_path
    proc = subprocess.Popen(cmd.split(), stdout=subprocess.PIPE)
    cert_verification = proc.stdout.read()
    if cert_verification==cert_path + ": OK\n":
        return True
    else:
        print "[!][" + now() + "] Received certificate (%s) isn't signed by server, something has gone wrong! Deleting certificate and aborting..." %(cert_path)
        os.remove(cert_path)
        exit()

def list_my_backups(mutual_conn, client_name, tag="ALL"):
    print "[+][" + now() + "] Client-Server: 'LIST-MY-BACKUPS'"
    mutual_conn.send("LIST-MY-BACKUPS")
    mutual_conn, individual_backups_list = read_in_chunks(mutual_conn)
    mutual_conn, shared_backups_list = read_in_chunks(mutual_conn)
    if tag=="ALL" or tag=="Individual-Only":
        print "[x] You have the following individual backup directories: "
        for i, individual_backup_directory in enumerate(individual_backups_list):
            print "(" + str(i + 1) + ")" + " : " + individual_backup_directory
    if tag=="ALL" or tag=="Shared-Only":
        print "[x] You have the following shared backup directories: "
        for i, shared_backup_directory in enumerate(shared_backups_list):
            print "(" + str(i + 1) + ")" + " : " + shared_backup_directory
    return mutual_conn, individual_backups_list, shared_backups_list

def client():
    client_name = verify_pre_conditions()
    simple_banner = "###################### SIRS-CLIENT ######################"
    print simple_banner

    HOST = "127.0.0.1"        # testing in local host (change if needed)
    PORT = 1337               # server port
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

    # TLS VERSION USED: TLSv1.2
    # the purpose of this ssl wrapper is to authenticate the server to the client
    initial_ssl_context = ssl.SSLContext(ssl.PROTOCOL_TLSv1_2)
    # tell the SSLContext that we want our peer's (server) certificate and its inherent CA validation
    initial_ssl_context.verify_mode = ssl.CERT_REQUIRED
    # we have a fake domain name in the server certificate, which we will verify
    initial_ssl_context.check_hostname = True

    # server auth
    # load our trusted certificate authority certificate to check if it is the same CA that
    # validated the server certificate we are going to receive from the server in a step ahead
    # (this goes with our assumption that client has the CA certificate previously installed)
    initial_ssl_context.load_verify_locations(clientside_trustanchor_path)

    # conn object requires a certificate signed by the specific CA because of the context object
    conn = initial_ssl_context.wrap_socket(sock, server_side=False, server_hostname = "*.sirs-server.org", do_handshake_on_connect=True)

    # CONNECTION
    # if the connection is successful, then the presented certificate was signed by the CA certificate we provided above
    conn.connect((HOST, PORT))
    print "[+][" + now() + "] Started a %s connection with the server." %(conn.version())

    # if this reached this point, the server's certificate is trusted and we have a basic TLS connection between our
    # client and our server. The client now knows he's talking to the right server.
    print "[+][" + now() + "] Client-Server: 'HELLO' (server is trusted)"
    conn.send("HELLO")
    if conn.read() != OK_MSG:
        print "[!][" + now() + "] Server didn't respond to my hello."
        exit()

    client_name = sanitize_clientname(client_name)
    print "[+][" + now() + "] Client-Server: 'NAME: %s'" %(client_name)
    conn.send("NAME: " + client_name)
    registered_status = conn.read()

    if registered_status == "REGISTERED":
        registered_status = True
    elif registered_status == "NOT-REGISTERED":
        registered_status = False
    else:
        print "[!][" + now() + "] Something went wrong, aborting..."
        exit()

    if args.register and registered_status:
        print "[!][" + now() + "] Server says you are already registered. Aborting..."
        exit()
    elif args.login and not registered_status:
        print "[!][" + now() + "] Server says you are not registered yet. Aborting..."
        exit()
    # REGISTER CODE BLOCK
    elif args.register and not registered_status: 
        # generating csr and sending to server
        cert_sign_request = locally_generate_csr(client_name, "utils")
        print "[+][" + now() + "] Client-Server: 'REGISTER'"
        conn.send("REGISTER")
        if conn.read() != OK_MSG:
            print "[!][" + now() + "] Server didn't respond to my certificate signing request."
            exit()
        # send CSR to server
        cert_sign_request_len = len(cert_sign_request)
        conn.send(str(cert_sign_request_len))
        conn.send(cert_sign_request)
        # catch certificate len
        cert_len = int(conn.read())
        mycert = conn.recv(cert_len)
        print "[+][" + now() + "] Received the signed certificate from the server. I'm storing it for further communications"
        mycert_path = mycert_dir + os.sep + client_name + ".crt"
        f = open(mycert_path,"w")
        f.write(mycert)
        f.close()
        os.remove(mycert_dir + os.sep + "sirs-client.csr")
        verify_received_certificate(mycert_path)
        if conn.read() != OK_MSG:
            print "[!][" + now() + "] Register not successful :("
            exit()
        print "[+][" + now() + "] Register successful :)"
        # done with server
    # mutual-TLS: https://en.wikipedia.org/wiki/Mutual_authentication (certificate based)
    else:
        # LOGIN CODE BLOCK
        if args.login and registered_status:
            print "[+][" + now() + "] Client-Server: 'LOGIN'"
            conn.send("LOGIN")
            # client-side: mutual_ssl_context IS EQUAL to initial_ssl_context in this first steps, so the same assurances described earlier are given
            mutual_ssl_context = ssl.SSLContext(ssl.PROTOCOL_TLSv1_2)
            mutual_ssl_context.verify_mode = ssl.CERT_REQUIRED
            mutual_ssl_context.check_hostname = True
            # server auth
            mutual_ssl_context.load_verify_locations(clientside_trustanchor_path)
            # load necessary files to authenticate through the TLS connection (client certificate and private key)
            mycertfile_path = mycert_dir + os.sep + client_name + ".crt"
            mykeyfile_path = mycert_dir + os.sep + client_name + ".key"
            mutual_ssl_context.load_cert_chain(certfile=mycertfile_path, keyfile=mykeyfile_path)
            # create new ssl socket object based on the set parameters
            mutual_conn = mutual_ssl_context.wrap_socket(conn, server_side=False, server_hostname = "*.sirs-server.org", do_handshake_on_connect=True)
            if mutual_conn.read() != OK_MSG:
                print "[!][" + now() + "] Login not successful :("
                exit()
            print "[+][" + now() + "] Login successful :)"
            # not yet done with server (possibly, or else you authenticated your channel just to close it after)
        # LIST MY FILES (INDIVIDUAL AND SHARED)
        if args.listmyfiles:
            mutual_conn = list_my_files(mutual_conn, client_name)
        # LIST SERVER USERS
        if args.listallusers:
            print "[+][" + now() + "] Client-Server: 'LIST-ALL-USERS'"
            mutual_conn.send("LIST-ALL-USERS")
            mutual_conn, server_users_list = read_in_chunks(mutual_conn)
            print "[x] Server users: %s" %(server_users_list)
        if args.listmybackups:
            mutual_conn, individual_backups_list, shared_backups_list = list_my_backups(mutual_conn, client_name)
        # SYNCHRONIZE CODE BLOCK (CLIENT-SERVER)
        if args.synchronize:
            if myfiles_dir not in os.path.commonprefix((os.path.realpath(args.synchronize),os.path.abspath(myfiles_dir))):
                print "[!][" + now() + "] Please provide me with a file or directory inside the \"myfiles\" directory. Aborting..."
                exit()
            print "[+][" + now() + "] Client-Server: 'SYNCHRONIZE' (send my files to server)"
            mutual_conn.send("SYNCHRONIZE")
            clientside_path = os.path.relpath(args.synchronize)
            file_structure = create_file_structure(clientside_path, client_name)
            mutual_conn = send_in_chunks(mutual_conn, file_structure)
            if mutual_conn.read() != OK_MSG:
                print "[!][" + now() + "] Synchronize not successful :("
                exit()
            print "[+][" + now() + "] Synchronize successful :)"
        # SYNCHRONIZE-ALL-INDIVIDUAL CODE BLOCK (CLIENT-SERVER)
        elif args.synchronizeallindiv:
            print "[+][" + now() + "] Client-Server: 'SYNCHRONIZE ALL' (send my files recursively to server)"
            mutual_conn.send("SYNCHRONIZE ALL")
            file_structure = create_file_structure(myfiles_dir, client_name)
            mutual_conn = send_in_chunks(mutual_conn, file_structure)
            if mutual_conn.read() != OK_MSG:
                print "[!][" + now() + "] Synchronize-all not successful :("
                exit()
            print "[+][" + now() + "] Synchronize-all successful :)"
        # FETCH CODE BLOCK (SERVER-CLIENT)
        elif args.fetch:
            mutual_conn = list_my_files(mutual_conn, client_name, tag="Individual-Only")
            if myfiles_dir not in os.path.commonprefix((os.path.realpath(args.fetch),os.path.abspath(myfiles_dir))):
                print "[!][" + now() + "] Please provide me with a file or directory inside the \"myfiles\" directory. Aborting..."
                exit()
            clientside_path = os.path.relpath(args.fetch)
            print "[+][" + now() + "] Client-Server: 'FETCH' (fetch \"%s\")." %(clientside_path)
            mutual_conn.send("FETCH")
            mutual_conn.send(clientside_path)
            mutual_conn, file_structure = read_in_chunks(mutual_conn)
            if mutual_conn.read() != OK_MSG:
                print "[!][" + now() + "] Fetch not successful :("
                exit()
            print "[+][" + now() + "] Fetch successful :)"
            reconstruct_client_files(file_structure, myfiles_dir, client_name)
        # FETCH-ALL-INDIVIDUAL CODE BLOCK (SERVER-CLIENT)
        elif args.fetchallindiv:
            mutual_conn = list_my_files(mutual_conn, client_name, tag="Individual-Only")
            print "[+][" + now() + "] Client-Server: 'FETCHALL' (fetch my files recursively from server)"
            mutual_conn.send("FETCHALL")
            mutual_conn, file_structure = read_in_chunks(mutual_conn)
            if mutual_conn.read() != OK_MSG:
                print "[!][" + now() + "] Fetch-all not successful :("
                exit()
            print "[+][" + now() + "] Fetch-all successful :)"
            reconstruct_client_files(file_structure, myfiles_dir, client_name)
        # SHARE FILE WITH ANOTHER USER
        elif args.share:
            input_path = args.share
            print "[+][" + now() + "] Client-Server: 'LIST-ALL-USERS'"
            mutual_conn.send("LIST-ALL-USERS")
            mutual_conn, server_users_list = read_in_chunks(mutual_conn)
            print "Server users: %s" %(server_users_list)
            
            # client interaction to determine sharee users
            chosen_users_repr = raw_input("Choose the users you want to share it with (separe them with \",\"): ")

            chosen_sharees_list = chosen_users_repr.split(",")
            chosen_sharees_list = [sanitize_clientname(sharee) for sharee in chosen_sharees_list]
            for chosen_sharee in chosen_sharees_list:
                if chosen_sharee==client_name:
                    print "[!][" + now() + "] You cannot choose yourself (%s). Aborting..." %(client_name) 
                    exit()
                if chosen_sharee not in server_users_list:
                    print "[!][" + now() + "] You cannot choose someone who isn't registered. Aborting..."
                    exit()
            filebasename = os.path.basename(input_path)
            input_directory = os.path.dirname(input_path)
            clientside_directory = mysharedfiles_dir + os.sep + client_name
            chosen_sharees_list = sorted(chosen_sharees_list)
            for chosen_sharee in chosen_sharees_list:
                clientside_directory += "-" + chosen_sharee
            mkdir_p(clientside_directory)
            
            clientside_path = input_path.replace(input_directory, clientside_directory)
            print "[+][" + now() + "] Copying file to \"%s\" directory. Work on that copy from now on as that's where the fetched shared files are going to." %(clientside_directory)
            recursive_copy_cmd = "cp -r " + input_path + " " + clientside_path
            subprocess.check_call(recursive_copy_cmd.split(), stdout=open(os.devnull), stderr=subprocess.STDOUT)
            print "[+][" + now() + "] Client-Server: 'SHARE' (sharing my files with chosen users)"
            mutual_conn.send("SHARE")
            share_info = [clientside_path, chosen_sharees_list]
            mutual_conn = send_in_chunks(mutual_conn, share_info)
            mutual_conn, user_certs = read_in_chunks(mutual_conn)
            sharedfile_structure = dict()
            sharedfile_structure[clientside_directory] = dict()
            if os.path.isfile(clientside_path):
                sharedfile_structure = sharedfile_prepare(clientside_path, filebasename, user_certs, client_name, sharedfile_structure)
            elif os.path.isdir(clientside_path):
                sharedfile_structure = filestructure_prepare(clientside_path, "not-needed", client_name, sharedfile_structure, user_certs=user_certs, sharedfiles_flag=True)
            else:
                print "[!][" + now() + "] You are trying to synchronize a non-existent file or directory. Aborting..."
                exit()
            mutual_conn = send_in_chunks(mutual_conn, sharedfile_structure)
            if mutual_conn.read() != OK_MSG:
                print "[!][" + now() + "] Share not successful :("
                exit()
            print "[+][" + now() + "] Share successful :)"
            print "[+][" + now() + "] You can now work in \"%s\"." %(clientside_path)
        elif args.fetchshared:
            mutual_conn = list_my_files(mutual_conn, client_name, tag="Shared-Only")
            if mysharedfiles_dir not in os.path.commonprefix((os.path.realpath(args.fetchshared),os.path.abspath(mysharedfiles_dir))):
                print "[!][" + now() + "] Please provide me with a file or directory inside the \"mysharedfiles\" directory. Aborting..."
                exit()
            clientside_path = os.path.relpath(args.fetchshared)
            print "[+][" + now() + "] Client-Server: 'FETCH-SHARED' (fetch \"%s\")." %(clientside_path)
            mutual_conn.send("FETCH-SHARED")
            mutual_conn.send(clientside_path)
            mutual_conn, sharedfile_structure = read_in_chunks(mutual_conn)
            if mutual_conn.read() != OK_MSG:
                print "[!][" + now() + "] Fetch-shared not successful :("
                exit()
            print "[+][" + now() + "] Fetch-shared successful :)"
            reconstruct_client_files(sharedfile_structure, mysharedfiles_dir, client_name, sharedfiles_flag=True)
        elif args.synchronizeshared:
            mutual_conn = list_my_files(mutual_conn, client_name, tag="Shared-Only")
            if mysharedfiles_dir not in os.path.commonprefix((os.path.realpath(args.synchronizeshared),os.path.abspath(mysharedfiles_dir))):
                print "[!][" + now() + "] Please provide me with a file or directory inside the \"mysharedfiles\" directory. Aborting..."
                exit()
            clientside_path = os.path.relpath(args.synchronizeshared)
            filebasename = os.path.basename(clientside_path)
            print "[+][" + now() + "] Client-Server: 'SYNCHRONIZE-SHARED' (synchronize \"%s\")." %(clientside_path)
            mutual_conn.send("SYNCHRONIZE-SHARED")

            sharedfile_structure = create_file_structure(clientside_path, client_name)
            for directory in sharedfile_structure:
                sharedfile_structure[directory] = dict()
            input_creator_sharees_repr = sharedfile_structure.keys()[0].split(os.sep)[1]
            chosen_sharees_list = input_creator_sharees_repr.split("-")
            share_info = [clientside_path, chosen_sharees_list]

            mutual_conn = send_in_chunks(mutual_conn, share_info)
            mutual_conn, user_certs = read_in_chunks(mutual_conn)

            if os.path.isfile(clientside_path):
                sharedfile_structure = sharedfile_prepare(clientside_path, filebasename, user_certs, client_name, sharedfile_structure)
            elif os.path.isdir(clientside_path):
                sharedfile_structure = filestructure_prepare(clientside_path, "not-needed", client_name, sharedfile_structure, user_certs=user_certs, sharedfiles_flag=True)
            else:
                print "[!][" + now() + "] You are trying to synchronize a non-existent file or directory. Aborting..."
                exit()
            mutual_conn = send_in_chunks(mutual_conn, sharedfile_structure)
            if mutual_conn.read() != OK_MSG:
                print "[!][" + now() + "] Synchronize-shared not successful :("
                exit()
            print "[+][" + now() + "] Synchronize-shared successful :)"
        elif args.revert:
            mutual_conn, individual_backups_list, shared_backups_list = list_my_backups(mutual_conn, client_name, "Individual-Only")
            if not individual_backups_list:
                print "[!][" + now() + "] You don't have any individual-backup on the server yet. Aborting..."
                exit()
            chosen_index = raw_input("Please insert the index number of the individual check-point you want to restore: ")
            try:
                chosen_index = int(chosen_index)-1
            except ValueError:
                print "[!][" + now() + "] Please insert an integer. You are trying to insert anything else but a valid index number. Aborting..."
                exit()

            if chosen_index < 0:
                print "[!][" + now() + "] Please insert an integer in the range printed out above. Aborting..."
                exit()
            try:
                chosen_backup_directory = individual_backups_list[chosen_index]
            except IndexError:
                print "[!][" + now() + "] Please insert an integer in the range printed out above. Aborting..."
                exit()

            mutual_conn.send("REVERT")
            mutual_conn = send_in_chunks(mutual_conn, chosen_backup_directory)
            mutual_conn, file_structure_list = read_in_chunks(mutual_conn)
            for file_structure in file_structure_list:
                reconstruct_client_files(file_structure, myfiles_dir, client_name)

            if mutual_conn.read() != OK_MSG:
                print "[!][" + now() + "] Revert-individual not successful :("
                exit()
            print "[+][" + now() + "] Revert-individual successful :)"
        elif args.revertshared:
            mutual_conn, individual_backups_list, shared_backups_list = list_my_backups(mutual_conn, client_name, "Shared-Only")
            if not shared_backups_list:
                print "[!][" + now() + "] You don't have any shared-backup on the server yet. Aborting..."
                exit()
            chosen_index = raw_input("Please insert the index number of the shared check-point you want to restore: ")
            try:
                chosen_index = int(chosen_index)-1
            except ValueError:
                print "[!][" + now() + "] Please insert an integer. You are trying to insert anything else but a valid index number. Aborting..."
                exit()

            if chosen_index < 0:
                print "[!][" + now() + "] Please insert an integer in the range printed out above. Aborting..."
                exit()
            try:
                chosen_backup_directory = shared_backups_list[chosen_index]
            except IndexError:
                print "[!][" + now() + "] Please insert an integer in the range printed out above. Aborting..."
                exit()

            mutual_conn.send("REVERT-SHARED")
            mutual_conn = send_in_chunks(mutual_conn, chosen_backup_directory)
            mutual_conn, file_structure_list = read_in_chunks(mutual_conn)
            for file_structure in file_structure_list:
                reconstruct_client_files(file_structure, mysharedfiles_dir, client_name, sharedfiles_flag=True)

            if mutual_conn.read() != OK_MSG:
                print "[!][" + now() + "] Revert-shared not successful :("
                exit()
            print "[+][" + now() + "] Revert-shared successful :)"
        elif args.deleteindividual:
            print "[+][" + now() + "] Client-Server: 'DELETE-FILE' (delete \"%s\")." %(args.deleteindividual)
            mutual_conn.send("DELETE-FILE")
            mutual_conn.send(args.deleteindividual)
            print "[+][" + now() + "] Asking to delete a local file or dir from the server (individual)."
            if mutual_conn.read() != OK_MSG:
                print "[!][" + now() + "] Delete-individual not successful :("
                exit()
            print "[+][" + now() + "] Delete-individual successful :)"
# global variables / initialization
mycert_dir = "utils" + os.sep + "mycerts"
shareuser_certs_dir = mycert_dir + os.sep + "sharee_certs"
myfiles_dir = "myfiles"
mysharedfiles_dir = "mysharedfiles"
mkdir_p(mycert_dir)
mkdir_p(shareuser_certs_dir)
mkdir_p(myfiles_dir)
mkdir_p(mysharedfiles_dir)
clientside_trustanchor_path = "utils" + os.sep + "sirs-ca.crt"
clientside_certificates_trustanchor_path = "utils" + os.sep + "sirs-cli-signing-ca.crt"

client()
