# SERVER
try:
    import socket
    import ssl
    import os
    import errno
    import time
    import datetime
    import json
    import subprocess
    import threading
except ImportError:
    raise ImportError("You need to do 'pip install -r requirements.txt' to be able to use this program.")

# PRELIMINARY NOTE: read the README.txt for informations about how to run this file
# READING:
# [!]: error information
# [+]: normal information

def mkdir_p(path):
    try:
        os.makedirs(path)
    except OSError as exc:  # Python >2.5
        if exc.errno == errno.EEXIST and os.path.isdir(path):
            pass
        else:
            raise

def get_client_loggedin_status(client_ip, serving_port, client_name, conn_tracker):
    try:
        loggedin_status = conn_tracker[(client_ip, serving_port)][2]
        loggedin_status = (loggedin_status=="LOGIN")
        if not loggedin_status:
            print "[!][" + now() + "] Cutting off connection with ip %s in port %s. Action requires client authentication..." %(client_ip, serving_port)
            return False
        print "[+][" + now() + "] Client %s is authenticated." %(client_name)
        return True
    except IndexError:
        print "[!][" + now() + "] Cutting off connection with ip %s in port %s. Action requires client authentication..." %(client_ip, serving_port)
        return False  # bye client

# (returns False if conn_tracker isn't correctly populated, returns the client_name otherwise)
def get_clientname(client_ip, serving_port, conn_tracker):
    try:
        client_name = conn_tracker[(client_ip, serving_port)][1]
        return client_name
    except KeyError:
        print "[!][" + now() + "] Cutting off connection with ip %s in port %s. No hello message..." %(client_ip, serving_port)
        return False  # bye client
    except IndexError:
        print "[!][" + now() + "] Cutting off connection with ip %s in port %s. No name message..." %(client_ip, serving_port)
        return False  # bye client

def fs_getalldirs(currentside_dirname, remoteside_dirname, file_structure):
    for local_filepath in os.listdir(currentside_dirname):
        currentside_filepath = currentside_dirname + os.sep + local_filepath
        if os.path.isdir(currentside_filepath):
            remoteside_filepath = remoteside_dirname + os.sep + local_filepath
            file_structure[remoteside_filepath] = os.listdir(currentside_filepath)
            file_structure = fs_getalldirs(currentside_filepath, remoteside_filepath, file_structure)
    return file_structure

def file_server2client(serverside_filepath, clientside_directory, filename, file_structure, file_content_flag=True, sharedfile_username=""):
    if os.path.isdir(serverside_filepath):
        pass    # no need to do anything if it's a directory
    else:
        if filename.endswith(".key.encrypted") or filename.endswith(".key.encrypted." + sharedfile_username):
            f = open(serverside_filepath)
            filecontent = f.read()
            filecontent = filecontent.encode("hex")
            f.close()
        elif filename.endswith(".sig"):
            f = open(serverside_filepath)
            filecontent = f.read()
            filecontent = filecontent.encode("hex")
            f.close()
        elif filename.endswith(".encrypted"):
            f = open(serverside_filepath)
            filecontent = f.read()
            filecontent = filecontent.encode("hex")
            f.close()
        else:
            # return untouched file_structure if the key is from another user whom we shared a file with
            return file_structure
        mtime = os.path.getmtime(serverside_filepath)
        mtime = get_time_repr(mtime)
        if file_content_flag:
            file_structure[clientside_directory][filename] = [filecontent, mtime]
        else:
            file_structure[clientside_directory][filename] = mtime
    return file_structure

def fs_server2client(serverside_dirpath, clientside_dirpath, file_content_flag=True, sharedfile_username=""):
    file_structure = dict()
    file_structure[clientside_dirpath] = dict()
    file_structure = fs_getalldirs(serverside_dirpath, clientside_dirpath, file_structure)
    # clean all dictionary values before we populate them
    for directory in file_structure:
        file_structure[directory] = dict()
    serverside_dirlist = [directory.replace(clientside_dirpath, serverside_dirpath, 1) for directory in file_structure]
    for serverside_directory in serverside_dirlist:
        clientside_directory = serverside_directory.replace(serverside_dirpath, clientside_dirpath, 1)
        for filename in os.listdir(serverside_directory):
            # append the file-names only to the respective directory
            serverside_filepath = serverside_directory + os.sep + filename
            file_structure = file_server2client(serverside_filepath, clientside_directory, filename, file_structure, file_content_flag, sharedfile_username)
    return file_structure

# update json file with clients information
def update_json_file(client_name, registered_status):
    clients_info[client_name] = [registered_status]
    f = open(client_json_filename, 'w')
    json.dump(clients_info, f)
    f.close()

def get_subject(client_cert):
    subject_str = "Subject: "
    for elem in client_cert['subject']:
        if len(elem)!=1:
            return False
        crt_param = elem[0]
        if len(crt_param)!=2:
            return False
        if crt_param[0]=="countryName":
            subject_str += "C = %s, " %(crt_param[1])
        elif crt_param[0]=="stateOrProvinceName":
            subject_str += "ST = %s, " %(crt_param[1])
        elif crt_param[0]=="localityName":
            subject_str += "L = %s, " %(crt_param[1])
        elif crt_param[0]=="organizationName":
            subject_str += "O = %s, " %(crt_param[1])
        elif crt_param[0]=="commonName":
            subject_str += "CN = %s" %(crt_param[1])
    return subject_str

# have in mind this alone cannot make up for verifying a client's identity,
# we also need to make sure client's certificate is signed by our trusted issuer,
# i.e., by our client certificate signing CA
def verify_cert_subject(client_cert, correct_subject_info, client_name):
    print "[+][" + now() + "] Verifying if m-TLS peer's certificate subject matches with client %s's specification." %(client_name)
    # construct subject string from received client certificate
    return get_subject(client_cert)==correct_subject_info

# in case client-side protection has been lift-off, this will sanitize the client name again for us
# it will also notify that something's wrong
def verify_clientname(client_name):
    removed_str_list = [" ", "\"", "'", "\\", "/", ".", "-", ";", "\n", "=", ",", "*", "@", "%", "$", "!"]
    for character in removed_str_list:
        if character in client_name:
            return False
    return True

def now():
    return datetime.datetime.fromtimestamp(time.time()).strftime('%Y-%m-%d %H:%M:%S')

def get_time_repr(timestamp):
    return datetime.datetime.fromtimestamp(timestamp).strftime('%Y-%m-%d %H:%M:%S')

# close CONNECTION socket
def server_close_connection_socket(conn, serving_port):
    # NOTE: have in mind the difference between a 'listening socket' and a 'connection socket'.
    # Closing a listening socket doesn't require to warn the client like when closing a connection socket
    conn.close()
    open_sockets.remove(conn)
    print "[+][" + now() + "] I'm releasing a socket on port %s. It is now available for use." %(serving_port)

def server_send_nok(conn, client_name):
    print "[+][" + now() + "] Server-Client(%s): 'NOK'" %(client_name)
    conn.send(NOK_MSG)
    return conn

def server_send_ok(conn, client_name):
    print "[+][" + now() + "] Server-Client(%s): 'OK'" %(client_name)
    conn.send(OK_MSG)
    return conn

def server_get_send_regstatus(conn, client_name, send):
    if client_name in clients_info and clients_info[client_name][0]:
        if send:
            print "[+][" + now() + "] Server-Client(%s): 'REGISTERED'" %(client_name)
            conn.send("REGISTERED")
        return conn, True
    else:
        if send:
            print "[+][" + now() + "] Server-Client(%s): 'NOT-REGISTERED'" %(client_name)
            conn.send("NOT-REGISTERED")
        return conn, False

def server_send_clientcert(conn, client_certificate_path, client_name):
    # send client his certificate signed by us, the server
    f = open(client_certificate_path)
    client_cert = f.read()
    f.close()
    print "[+][" + now() + "] Sending client %s his signed certificate.'" %(client_name)
    conn.send(str(len(client_cert)))
    conn.send(client_cert)

def server_sign_clientcert(client_csr_path, client_csr, client_name):
    f = open(client_csr_path,"w")
    f.write(client_csr)
    f.close()
    # verify client certificate matches username
    print "[+][" + now() + "] Verifying %s's certificate signing request..." %(client_name)
    cmd = "openssl req -text -noout -verify -in " + client_csr_path
    proc = subprocess.Popen(cmd.split(), stdout=subprocess.PIPE, stderr=open(os.devnull))
    csr_info = proc.stdout.read()
    correct_subject_info = "Subject: C = PT, ST = Lisboa, L = Lisboa, O = " + client_name + ", CN = *." + client_name + ".org"
    correct_subject_info_deprecated_openssl = "Subject: C=PT, ST=Lisboa, L=Lisboa, O=" + client_name + ", CN=*." + client_name + ".org"

    csr_info = csr_info.split("\n")
    csr_info = [elem.strip() for elem in csr_info]
    # 4th element corresponds to client's subject information
    if csr_info[3] in(correct_subject_info, correct_subject_info_deprecated_openssl):
        print "[+][" + now() + "] %s's certificate signing request subject verified." %(client_name)
    else:
        # the CSR was modified in a way that it doesn't identify the current client
        # BUG-NOTE: if this happens, the client would be hanging waiting for the signed certificate, but that's not expected behavior :) 
        print "[!][" + now() + "] Cutting off connection... someone modified the certificate signing request in a way that it doesn't have the correct information about client %s" %(client_name)
        os.remove(client_csr_path)
        return False
    # signing client certificate
    print "[+][" + now() + "] Signing %s's certificate and storing it in the default certificates directory..." %(client_name)
    cmd = "." + os.sep + "SIGN_CLIENT_CERT.sh " + client_csr_path
    subprocess.check_call(cmd.split(), stdout=open(os.devnull), stderr=subprocess.STDOUT)
    os.remove(client_csr_path)
    return True


def say_bye(client_ip, serving_port, conn_tracker):
    try:
        client_name = conn_tracker[(client_ip, serving_port)][1]
        # CONN-TRACK
        conn_tracker.pop((client_ip, serving_port))
    except KeyError:
        client_name = str((client_ip, serving_port))
    except IndexError:
        client_name = str((client_ip, serving_port))
        conn_tracker.pop((client_ip, serving_port))
    print "[+][" + now() + "] Client %s disconnected." %(client_name)
    return conn_tracker

def deal_with_client(conn, client_ip, serving_port):
    conn_tracker = dict()
    new_conn = conn
    data = new_conn.read()
    # null data means the client is finished with us
    while data:
        new_conn, conn_continue, conn_tracker = interact_with_client(new_conn, data, client_ip, serving_port, conn_tracker)
        if not conn_continue:
            break
        data = new_conn.read()
    # finished with client
    conn_tracker = say_bye(client_ip, serving_port, conn_tracker)

# detect and prevent path-traversal attacks in this file structure by denying access to upper directories
def path_traversal_verified(suspect_filepath, highestlevel_dirname):
    if os.path.commonprefix((os.path.realpath(suspect_filepath),os.path.abspath(highestlevel_dirname))) != os.path.abspath(highestlevel_dirname):
        return False
    return True

def sandbox_escaped(currentside_filepath, currentside_dirname, conn, client_name):
    if not path_traversal_verified(currentside_filepath, currentside_dirname):
        #print currentside_filepath
        #print currentside_dirname
        print "[!][" + now() + "] Client %s just tried to escape his directory." %(client_name)
        conn = server_send_nok(conn, client_name)
        return True
    return False

def fetch_files_dirs(serverside_path, clientside_path, client_name, sharedfile_username=""):
    serverside_directory = os.path.dirname(serverside_path)
    clientside_directory = os.path.dirname(clientside_path)

    file_structure = dict()
    if os.path.isdir(serverside_path):
        file_structure = fs_server2client(serverside_path, clientside_path, True, sharedfile_username)
    else:
        file_structure[clientside_directory] = dict()
        file_filename = os.path.basename(clientside_path) + ".encrypted"
        key_filename = os.path.basename(clientside_path) + ".key.encrypted" if not sharedfile_username else os.path.basename(clientside_path) + ".key.encrypted." + sharedfile_username
        sig_filename = os.path.basename(clientside_path) + ".sig"
        serverside_filepath = serverside_directory + os.sep + file_filename
        serverside_keypath = serverside_directory + os.sep + key_filename
        serverside_sigpath = serverside_directory + os.sep + sig_filename
        if os.path.isfile(serverside_filepath) and os.path.isfile(serverside_keypath) and os.path.isfile(serverside_sigpath):
            file_structure = file_server2client(serverside_filepath, clientside_directory, file_filename, file_structure, True, sharedfile_username)
            file_structure = file_server2client(serverside_keypath, clientside_directory, key_filename, file_structure, True, sharedfile_username)
            file_structure = file_server2client(serverside_sigpath, clientside_directory, sig_filename, file_structure, True, sharedfile_username)
        else:
            print "[!][" + now() + "] Client %s is trying to fetch a non-existent file. Cutting connection off..." %(client_name)
            return file_structure, False   # bye client
    return file_structure, True

def read_in_chunks(conn, client_name):
    # handle unexpected data
    try: 
        data_len = int(conn.read())
    except ValueError:
        print "[!][" + now() + "] Client %s tried to send me a string that does not correspond to an integer. Cutting off connection..." %(client_name)
        return conn, False  # bye client
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

def send_in_chunks(conn, data):
    data_repr = json.dumps(data)
    data_repr_len = len(data_repr)
    conn.send(str(data_repr_len))
    conn.send(data_repr)
    return conn

def get_user_cert_content(username):
    client_cert_path = client_certificates_dir + os.sep + username + ".crt"
    f = open(client_cert_path)
    client_cert_content = f.read()
    f.close()
    return client_cert_content
        
def verify_digital_signature(pubkey_path,sig_filepath,cryptogram_filepath):
    cmd = "openssl dgst -sha256 -verify " + pubkey_path + " -signature " + sig_filepath + " " + cryptogram_filepath
    proc = subprocess.Popen(cmd.split(), stdout=subprocess.PIPE)
    sig_verification = proc.stdout.read()
    return sig_verification=="Verified OK\n"

def write_and_verify_signature(signature_bytecode, serverside_filepath, backup_filepath, cryptogram_filepath, pubkey_path):
    signature = signature_bytecode.decode("hex")
    sig_filepath = serverside_filepath + ".sig"
    sig_backup_filepath = backup_filepath + ".sig"
    f = open(sig_filepath, "w")
    f.write(signature)
    f.close()
    f = open(sig_backup_filepath, "w")
    f.write(signature)
    f.close()
    sig_verified = verify_digital_signature(pubkey_path, sig_filepath, cryptogram_filepath)
    return sig_verified

def construct_client_files(conn, client_name, serverside_dirname, backup_dirname, clientside_dirname, sharedfiles_tag, file_structure):
    pubkey_path = "clients" + os.sep + "client_certs" + os.sep + client_name + ".pubkey"
    for clientside_directory in file_structure:
        serverside_directory = clientside_directory.replace(clientside_dirname,serverside_dirname, 1)  # replace only first occurence
        backup_directory = clientside_directory.replace(clientside_dirname,backup_dirname, 1)  # replace only first occurence
        if sandbox_escaped(serverside_directory, serverside_dirname, conn, client_name):
            return conn, False    # bye client
        mkdir_p(serverside_directory)
        for filename in file_structure[clientside_directory]:
            serverside_filepath = serverside_directory + os.sep + filename
            backup_filepath = backup_directory + os.sep + filename
            if sandbox_escaped(serverside_filepath, serverside_dirname, conn, client_name):
                return conn, False    # bye client
            encrypted_filecontent_bytecode = file_structure[clientside_directory][filename][0]
            encrypted_filecontent = encrypted_filecontent_bytecode.decode("hex")
            cryptogram_filepath = serverside_filepath + ".encrypted"
            cryptogram_backup_filepath = backup_filepath + ".encrypted"
            file_exists = os.path.exists(cryptogram_filepath)
            if sharedfiles_tag:
                clientside_writetime = file_structure[clientside_directory][filename][2]
                serverside_writetime = os.path.getmtime(cryptogram_filepath) if file_exists else 0
                if clientside_writetime >= serverside_writetime:
                    mkdir_p(backup_directory)       # only creates backup directory if a file in it has been altered
                    f = open(cryptogram_filepath, "w")
                    f.write(encrypted_filecontent)
                    f.close()
                    f = open(cryptogram_backup_filepath, "w")
                    f.write(encrypted_filecontent)
                    f.close()
                    signature_bytecode = file_structure[clientside_directory][filename][1]
                    sig_verified = write_and_verify_signature(signature_bytecode, serverside_filepath, backup_filepath, cryptogram_filepath, pubkey_path)
                    if not sig_verified:
                            print "[!][" + now() + "] Ciphered-file signature not verified: file \"%s\" wasn't signed by %s" %(cryptogram_filepath, client_name)
                            return conn, False    # bye client
                    encrypted_aeskeys = file_structure[clientside_directory][filename][3:]
                    for aeskey_info in encrypted_aeskeys:
                        username = aeskey_info[0]
                        encrypted_aeskey_bytecode = aeskey_info[1]
                        encrypted_aeskey = encrypted_aeskey_bytecode.decode("hex")
                        f = open(serverside_filepath + ".key.encrypted." + username, "w")
                        f.write(encrypted_aeskey)
                        f.close()
                        f = open(backup_filepath + ".key.encrypted." + username, "w")
                        f.write(encrypted_aeskey)
                        f.close()
            else:
                clientside_writetime = file_structure[clientside_directory][filename][3]
                serverside_writetime = os.path.getmtime(cryptogram_filepath) if file_exists else 0
                if clientside_writetime >= serverside_writetime:
                    mkdir_p(backup_directory)        # only creates backup directory if a file in it has been altered
                    f = open(cryptogram_filepath, "w")
                    f.write(encrypted_filecontent)
                    f.close()
                    f = open(cryptogram_backup_filepath, "w")
                    f.write(encrypted_filecontent)
                    f.close()
                    signature_bytecode = file_structure[clientside_directory][filename][2]
                    sig_verified = write_and_verify_signature(signature_bytecode, serverside_filepath, backup_filepath, cryptogram_filepath, pubkey_path)
                    if not sig_verified:
                            print "[!][" + now() + "] Ciphered-file signature not verified: file \"%s\" wasn't signed by %s" %(cryptogram_filepath, client_name)
                            return conn, False    # bye client
                    encrypted_aeskey_bytecode = file_structure[clientside_directory][filename][1]
                    encrypted_aeskey = encrypted_aeskey_bytecode.decode("hex")
                    f = open(serverside_filepath + ".key.encrypted", "w")
                    f.write(encrypted_aeskey)
                    f.close()
                    f = open(backup_filepath + ".key.encrypted", "w")
                    f.write(encrypted_aeskey)
                    f.close()
    return conn, True

def get_individual_backup_dirs(client_name):
    serverside_individual_dirname = individual_backup_files_dir + os.sep + client_name + "@"
    all_backup_dirs = sorted(os.listdir(individual_backup_files_dir))
    client_backup_dirs = []
    for client_backup_directory in all_backup_dirs:
        server_backup_file = individual_backup_files_dir + os.sep + client_backup_directory
        if serverside_individual_dirname in server_backup_file:
            client_backup_dirs.append(client_backup_directory.split(client_name + "@", 1)[-1])
    return client_backup_dirs

def get_shared_backup_dirs(client_name):
    all_backup_dirs = sorted(os.listdir(shared_backup_files_dir))
    client_backup_dirs = []
    for client_backup_directory in all_backup_dirs:
        client_names_list = client_backup_directory.split("@",1)[0].split("-")
        if client_name in client_names_list:
            client_backup_dirs.append(client_backup_directory)
    return client_backup_dirs

# note we assume register steps aren't compromised for real clients in the report,
# although we already provision for such events
# return values: (connection_socket, end_with_client)
def interact_with_client(conn, data, client_ip, serving_port, conn_tracker):
    print "CONNECTION TRACKER: %s" %(conn_tracker)
    # ----------------------
    # CLIENT HELLO MESSAGE |
    # ----------------------
    if data=="HELLO":
        print "[+][" + now() + "] Client with ip %s is connected and trusts me. I'm serving him in port %s, using %s." %(client_ip, serving_port, conn.version())
        conn = server_send_ok(conn, client_ip)
        # CONN-TRACK
        conn_tracker[(client_ip, serving_port)] = [data]
        return conn, True, conn_tracker
    # ---------------------
    # CLIENT NAME MESSAGE |
    # ---------------------
    elif "NAME: " in data:
        client_name = data.replace("NAME: ","", 1)
        try:
            # CONN-TRACK
            conn_tracker[(client_ip, serving_port)].append(client_name)
        except KeyError:
            print "[!][" + now() + "] Cutting off connection with ip %s in port %s. No hello message..." %(client_ip, serving_port)
            conn = server_send_nok(conn, client_ip)
            return conn, False, conn_tracker  # bye client

        if not client_name:
            print "[!][" + now() + "] Cutting off connection with ip %s in port %s. No client name found..." %(client_ip, serving_port)
            conn = server_send_nok(conn, client_ip)
            return conn, False, conn_tracker  # bye client

        # if client name has invalid characters, supposedly worked on the client-side, then the client is either removing client-side checks or
        # he was a victim of a man-in-the-middle attack (supposing our one-way TLS isn't secure enough, which is doubtful)
        verified_client_name = verify_clientname(client_name)
        if not verified_client_name:
            print "[!][" + now() + "] Client name is being tampered with, cutting off connection with ip %s in port %s..." %(client_ip, serving_port)
            conn = server_send_nok(conn, client_ip)
            return conn, False, conn_tracker    # bye client
        print "[+][" + now() + "] Client with ip %s, served in port %s, says his name is %s." %(client_ip, serving_port, client_name)
        # send client register status to client
        conn, registered_status = server_get_send_regstatus(conn, client_name, send=True)
        update_json_file(client_name, registered_status)
        return conn, True, conn_tracker
    # -----------------------------------------
    # CLIENT REGISTER AND CERTIFICATE SIGNING |
    # -----------------------------------------
    elif data=="REGISTER":
        client_name = get_clientname(client_ip, serving_port, conn_tracker)
        if not client_name:
            return conn, False, conn_tracker  # bye client

        print "[+][" + now() + "] Client %s wants to register." %(client_name)
        # check registered status, if he is registered and we are here, then something fishy is going on 
        # because either client-side checks have been surpassed or client name was changed on the fly.
        conn, registered = server_get_send_regstatus(conn, client_name, send=False)
        if registered:
            print "[!][" + now() + "] Client %s is already registered, cannot reregister, cutting off connection..." %(client_name)
            conn = server_send_nok(conn)
            return conn, False, conn_tracker    # bye client

        # confirm signing request is following previous rules
        conn = server_send_ok(conn, client_name)
        # handle unexpected data
        try: 
            cert_sign_request_len = int(conn.read())
        except ValueError:
            print "[!][" + now() + "] Client %s tried to send me a string that does not correspond to an integer. Cutting off connection..." %(client_name)
            return conn, False, conn_tracker  # bye client
        client_csr = conn.recv(cert_sign_request_len)
        client_csr_path = client_certificates_dir + os.sep + client_name + ".csr"
        client_certificate_path = client_certificates_dir + os.sep + client_name + ".crt"
        crt_verified = server_sign_clientcert(client_csr_path, client_csr, client_name)
        if not crt_verified:
            return conn, False, conn_tracker    # bye client
        # send this client his certificate
        server_send_clientcert(conn, client_certificate_path, client_name)
        # create this client's directory
        mkdir_p(individual_files_dir + os.sep + client_name)
        # setting registered_status to True
        update_json_file(client_name, True)
        conn = server_send_ok(conn, client_name)
        return conn, False, conn_tracker    # bye client
    # -------------------------------------------
    # CLIENT LOGIN AND MUTUAL-TLS (TWO-WAY TLS) |
    # -------------------------------------------
    elif data=="LOGIN":
        # from this moment on, the client shall have a certificate signed by the server, so we can
        # build a new SSLContext and tell it that we want to check our peer's (client) certificate 
        # and its inherent CA validation, respectively through a challenge-response mechanism (to 
        # prove the certificate is really of that client) and verifying the certificate's signer
        # against the given one by the client (the signer should be us, i.e., the certificate should
        # be "server.crt")
        # info: https://tools.ietf.org/html/rfc5929.html ('tls-unique' mode), read also about TLS renegotiation standards
        client_name = get_clientname(client_ip, serving_port, conn_tracker)
        if not client_name:
            return conn, False, conn_tracker  # bye client

        print "[+][" + now() + "] Client who said his name is %s wants to login." %(client_name)
        # the purpose of this ssl wrapper is to authenticate the client to the server
        mutual_ssl_context = ssl.SSLContext(ssl.PROTOCOL_TLSv1_2)
        # client auth: need to verify the client's given certificate was signed by our signing CA,
        # so load its path into the verifiable locations
        mutual_ssl_context.load_verify_locations("cli-signing-ca/sirs-cli-signing-ca.crt")
        # load necessary files to create a TLS connection (server certificate and private key)
        mutual_ssl_context.load_cert_chain(certfile="server/sirs-server.crt", keyfile="server/sirs-server.key")

        # we require a certificate from the client this time, signed by our server
        mutual_ssl_context.verify_mode = ssl.CERT_REQUIRED
        mutual_ssl_context.check_hostname = False
        print "[+][" + now() + "][M-TLS] Verifying if %s's certificate was indeed signed by us, i.e., by our client certificate signing CA." %(client_name)

        # instead of completely closing the connection now and starting a new one, simply rewrap the socket with our new SSL configuration
        # this will raise an Error if anything's wrong with the received certificate
        # try/except for the case of the client giving us a certificate that wasn't signed by us
        try:
            mutual_conn = mutual_ssl_context.wrap_socket(conn, server_side=True, do_handshake_on_connect=True)
        except ssl.SSLError as err:
            print "[!][" + now() + "] Client provided a certificate that wasn't signed by our certificate authority. Error: %s" %(repr(err))
            conn = server_send_nok(conn, client_name)
            return conn, False, conn_tracker   # bye client
        # issuer is verified already, so let's verify peer certificate subject to check if it matches our current client;
        # this is used as a protection against client-side tampering where the client sends us another client's certificate (that cannot be accepted)
        correct_subject_info = "Subject: C = PT, ST = Lisboa, L = Lisboa, O = " + client_name + ", CN = *." + client_name + ".org"
        client_cert =  mutual_conn.getpeercert()
        client_cert_verified = verify_cert_subject(client_cert, correct_subject_info, client_name)
        if not client_cert_verified:
            # FUTURE-WORK: it would be nice if we could add this certificate to a revogation list, and also check it... 
            # (no time for implementing CRLs and CRLs check in this project, unfortunately)
            print "[!][" + now() + "] Someone with a certificate signed by us is trying to start a session in the name of %s, but this certificate doesn't match the username. Certificate identity: '%s'"  %(client_name,get_subject(client_cert))
            conn = server_send_nok(mutual_conn, client_name)
            return mutual_conn, False, conn_tracker   # bye client
        
        conn = server_send_ok(mutual_conn, client_name)
        # CONN-TRACK
        conn_tracker[(client_ip, serving_port)].append(data)
        return mutual_conn, True, conn_tracker    # authenticated session from now on
    # -------------------------
    # LIST SYNCHRONIZED FILES |
    # -------------------------
    elif data=="LIST-MY-FILES":
        client_name = get_clientname(client_ip, serving_port, conn_tracker)
        if not client_name:
            return conn, False, conn_tracker  # bye client
        client_loggedin_status = get_client_loggedin_status(client_ip, serving_port, client_name, conn_tracker)
        if not client_loggedin_status:
            return conn, False, conn_tracker  # bye client
        print "[+][" + now() + "] Client %s wants to know what files he has synchronized with us (individual and shared)." %(client_name)
        serverside_individual_dirname = individual_files_dir + os.sep + client_name
        clientside_individual_dirname = "myfiles"
        individualfile_structure = fs_server2client(serverside_individual_dirname, clientside_individual_dirname, file_content_flag=False)
        conn = send_in_chunks(conn, individualfile_structure)
        creator_sharees_list = []
        for shared_directory in os.listdir(shared_files_dir):
            if client_name in shared_directory.split("-"):
                creator_sharees_list.append(shared_directory)

        sharedfile_structure_list = []
        for creator_sharees_repr in creator_sharees_list:
            serverside_shared_dirname = shared_files_dir + os.sep + creator_sharees_repr
            clientside_shared_dirname = "mysharedfiles" + os.sep + creator_sharees_repr
            sharedfile_structure = fs_server2client(serverside_shared_dirname, clientside_shared_dirname, file_content_flag=False)
            # remove other clients encrypted AES keys
            for shared_directory in sharedfile_structure:
                sharedfiles_list = sharedfile_structure[shared_directory].keys()
                for sharedfile in sharedfiles_list:
                    if sharedfile.endswith(".key.encrypted." + client_name):
                        continue
                    elif sharedfile.endswith(".encrypted"):
                        continue
                    else:
                        sharedfile_structure[shared_directory].pop(sharedfile)
            sharedfile_structure_list.append(sharedfile_structure)
        conn = send_in_chunks(conn, sharedfile_structure_list)
        return conn, True, conn_tracker    # continue connection, this action can be performed in conjunction with others
    # ----------------
    # LIST ALL USERS |
    # ----------------
    elif data=="LIST-ALL-USERS":
        client_name = get_clientname(client_ip, serving_port, conn_tracker)
        if not client_name:
            return conn, False, conn_tracker  # bye client
        client_loggedin_status = get_client_loggedin_status(client_ip, serving_port, client_name, conn_tracker)
        if not client_loggedin_status:
            return conn, False, conn_tracker  # bye client

        registered_client_names = []
        for elem_name in clients_info:
            registered_client = server_get_send_regstatus(conn, elem_name, send=False)[1]
            if registered_client:
                registered_client_names.append(elem_name)
        conn = send_in_chunks(conn, registered_client_names)
        return conn, True, conn_tracker
    # ------------------------------------------------------------------
    # SYNCHRONIZE / SYNCHRONIZE ALL (FILE-FLOW: FROM CLIENT TO SERVER) |
    # ------------------------------------------------------------------
    elif data=="SYNCHRONIZE" or data=="SYNCHRONIZE ALL":
        client_name = get_clientname(client_ip, serving_port, conn_tracker)
        if not client_name:
            return conn, False, conn_tracker  # bye client
        client_loggedin_status = get_client_loggedin_status(client_ip, serving_port, client_name, conn_tracker)
        if not client_loggedin_status:
            return conn, False, conn_tracker  # bye client
        print "[+][" + now() + "] Client %s wants to synchronize his individual files." %(client_name)
        conn, individualfile_structure = read_in_chunks(conn, client_name)
        if not individualfile_structure:
            return conn, False, conn_tracker  # bye client

        # create individual files server-side
        serverside_individual_dirname = individual_files_dir + os.sep + client_name
        backup_individual_dirname = individual_backup_files_dir + os.sep + client_name + "@" + now()
        clientside_individual_dirname = "myfiles"
        conn, sandbox_ok = construct_client_files(conn, client_name, serverside_individual_dirname, backup_individual_dirname, \
                clientside_individual_dirname, False, individualfile_structure)
        if not sandbox_ok:
            return conn, False, conn_tracker    # bye client
        conn = server_send_ok(conn, client_name)
        return conn, False, conn_tracker   # bye client
    # ------------------------------------------
    # FETCH (FILE-FLOW: FROM SERVER TO CLIENT) |
    # ------------------------------------------
    elif data=="FETCH":
        client_name = get_clientname(client_ip, serving_port, conn_tracker)
        if not client_name:
            return conn, False, conn_tracker  # bye client
        client_loggedin_status = get_client_loggedin_status(client_ip, serving_port, client_name, conn_tracker)
        if not client_loggedin_status:
            return conn, False, conn_tracker  # bye client
        print "[+][" + now() + "] Client %s wants to fetch an individual file or directory." %(client_name)
        serverside_individual_dirname = individual_files_dir + os.sep + client_name
        clientside_individual_dirname = "myfiles"
        input_path = conn.read()
        # handle unexpected data
        try:
            local_path = input_path.split(clientside_individual_dirname, 1)[1].lstrip(os.sep)
        except IndexError:
            print "[!][" + now() + "] Client %s sent an unexpected message. Cutting connection off..." %(client_name)
            return conn, False, conn_tracker
        clientside_path = clientside_individual_dirname + os.sep + local_path
        serverside_path = serverside_individual_dirname + os.sep + local_path
        individualfile_structure, good_output = fetch_files_dirs(serverside_path, clientside_path, client_name)
        if not good_output:
            return conn, False, conn_tracker   # bye client

        conn = send_in_chunks(conn, individualfile_structure)
        conn = server_send_ok(conn, client_name)
        return conn, False, conn_tracker   # bye client
    # ----------------------------------------------
    # FETCH ALL (FILE-FLOW: FROM SERVER TO CLIENT) |
    # ----------------------------------------------
    elif data=="FETCHALL":
        client_name = get_clientname(client_ip, serving_port, conn_tracker)
        if not client_name:
            return conn, False, conn_tracker  # bye client
        client_loggedin_status = get_client_loggedin_status(client_ip, serving_port, client_name, conn_tracker)
        if not client_loggedin_status:
            return conn, False, conn_tracker  # bye client
        print "[+][" + now() + "] Client %s wants to fetch all of his individual files." %(client_name)
        serverside_individual_dirname = individual_files_dir + os.sep + client_name
        clientside_individual_dirname = "myfiles"
        # put all client files in the file structure as they are (i.e., encrypted)
        file_structure = fs_server2client(serverside_individual_dirname, clientside_individual_dirname)
        conn = send_in_chunks(conn, file_structure)
        conn = server_send_ok(conn, client_name)
        return conn, False, conn_tracker    # bye client
    # ----------------------------------------------
    # SHARE (FILE-FLOW: FROM CLIENT TO SERVER)     |
    # ----------------------------------------------
    elif data=="SHARE":
        client_name = get_clientname(client_ip, serving_port, conn_tracker)
        if not client_name:
            return conn, False, conn_tracker  # bye client
        client_loggedin_status = get_client_loggedin_status(client_ip, serving_port, client_name, conn_tracker)
        if not client_loggedin_status:
            return conn, False, conn_tracker  # bye client

        conn, share_info = read_in_chunks(conn, client_name)
        if not share_info:
            return conn, False, conn_tracker  # bye client
        share_path = share_info[0]
        share_users = [client_name] + share_info[1]
        user_certs = dict()
        creator_sharees_repr = ""
        for username in share_users:
            user_cert = get_user_cert_content(username)
            user_certs[username] = user_cert
            creator_sharees_repr += username + "-"
        creator_sharees_repr = creator_sharees_repr.rstrip("-")
        conn = send_in_chunks(conn, user_certs)
        conn, sharedfile_structure = read_in_chunks(conn, client_name)
        if not sharedfile_structure:
            return conn, False, conn_tracker  # bye client

        # create shared files server-side
        serverside_shared_dirname = shared_files_dir + os.sep + creator_sharees_repr
        backup_shared_dirname = shared_backup_files_dir + os.sep + creator_sharees_repr + "@" + now()
        clientside_shared_dirname = "mysharedfiles" + os.sep + creator_sharees_repr
        conn, sandbox_ok = construct_client_files(conn, client_name, serverside_shared_dirname, backup_shared_dirname, \
                clientside_shared_dirname, True, sharedfile_structure)
        if not sandbox_ok:
            return conn, False, conn_tracker  # bye client
        
        conn = server_send_ok(conn, client_name)
        return conn, False, conn_tracker  # bye client
    # -----------------------------------------------------
    # FETCH-SHARED (FILE-FLOW: FROM CLIENT TO SERVER)     |
    # -----------------------------------------------------
    elif data=="FETCH-SHARED":
        client_name = get_clientname(client_ip, serving_port, conn_tracker)
        if not client_name:
            return conn, False, conn_tracker  # bye client
        client_loggedin_status = get_client_loggedin_status(client_ip, serving_port, client_name, conn_tracker)
        if not client_loggedin_status:
            return conn, False, conn_tracker  # bye client
        print "[+][" + now() + "] Client %s wants to fetch a shared file or directory." %(client_name)
        input_path = conn.read()
        try:
            local_path = input_path.split("mysharedfiles", 1)[1].lstrip(os.sep)
        except IndexError:
            print "[!][" + now() + "] Client %s sent an unexpected message. Cutting connection off..." %(client_name)
            return conn, False, conn_tracker    # bye client
        creator_sharees_repr = ""
        for shared_directory in os.listdir(shared_files_dir):
            input_creator_sharees_repr = local_path.split(os.sep, 1)[0]
            if client_name in shared_directory.split("-") and shared_directory==input_creator_sharees_repr:
                creator_sharees_repr = shared_directory
                break
        if not creator_sharees_repr:
            print "[!][" + now() + "] Client %s didn't send a correct share-directory. Cutting connection off..." %(client_name)
            return conn, False, conn_tracker    # bye client

        serverside_shared_dirname = shared_files_dir + os.sep + creator_sharees_repr
        clientside_shared_dirname = "mysharedfiles" + os.sep + creator_sharees_repr
        # handle unexpected data
        try:
            local_path = input_path.split(clientside_shared_dirname, 1)[1].lstrip(os.sep)
        except IndexError:
            print "[!][" + now() + "] Client %s sent an unexpected message. Cutting connection off..." %(client_name)
            return conn, False, conn_tracker    # bye client
        clientside_path = (clientside_shared_dirname + os.sep + local_path).rstrip(os.sep)
        serverside_path = (serverside_shared_dirname + os.sep + local_path).rstrip(os.sep)
        sharedfile_structure, good_output = fetch_files_dirs(serverside_path, clientside_path, client_name, sharedfile_username=client_name)
        if not good_output:
            return conn, False, conn_tracker    # bye client
        conn = send_in_chunks(conn, sharedfile_structure)
        conn = server_send_ok(conn, client_name)
        return conn, False, conn_tracker  # bye client
    # -------------------------------------------------------
    # SYNCHRONIZE-SHARED (FILE-FLOW: FROM CLIENT TO SERVER) |
    # -------------------------------------------------------
    elif data=="SYNCHRONIZE-SHARED":
        client_name = get_clientname(client_ip, serving_port, conn_tracker)
        if not client_name:
            return conn, False, conn_tracker  # bye client
        client_loggedin_status = get_client_loggedin_status(client_ip, serving_port, client_name, conn_tracker)
        if not client_loggedin_status:
            return conn, False, conn_tracker  # bye client
        print "[+][" + now() + "] Client %s wants to synchronize a shared file or directory." %(client_name)
        conn, share_info = read_in_chunks(conn, client_name)
        if not share_info:
            return conn, False, conn_tracker  # bye client
        share_path = share_info[0]
        share_users = [client_name] + share_info[1]
        user_certs = dict()
        creator_sharees_repr = ""
        for username in share_users:
            user_cert = get_user_cert_content(username)
            user_certs[username] = user_cert
            creator_sharees_repr += username + "-"
        creator_sharees_repr = creator_sharees_repr.rstrip("-")
        conn = send_in_chunks(conn, user_certs)

        conn, sharedfile_structure = read_in_chunks(conn, client_name)
        if not sharedfile_structure:
            return conn, False, conn_tracker  # bye client

        # example filepath
        input_creator_sharees_repr = sharedfile_structure.keys()[0].split(os.sep)[1]
        creator_sharees_repr = ""
        for shared_directory in os.listdir(shared_files_dir):
            if client_name in shared_directory.split("-") and shared_directory==input_creator_sharees_repr:
                creator_sharees_repr = shared_directory
                break
        if not creator_sharees_repr:
            print "[!][" + now() + "] Client %s didn't send a correct share-directory. Cutting connection off..." %(client_name)
            return conn, False, conn_tracker    # bye client

        # create individual files server-side
        serverside_shared_dirname = shared_files_dir + os.sep + creator_sharees_repr
        backup_shared_dirname = shared_backup_files_dir + os.sep + creator_sharees_repr + "@" + now()
        clientside_shared_dirname = "mysharedfiles" + os.sep + creator_sharees_repr
        conn, sandbox_ok = construct_client_files(conn, client_name, serverside_shared_dirname, backup_shared_dirname, \
                clientside_shared_dirname, True, sharedfile_structure)
        if not sandbox_ok:
            return conn, False, conn_tracker    # bye client
        conn = server_send_ok(conn, client_name)
        return conn, False, conn_tracker  # bye client
    # --------------------------------------------------
    # LIST CLIENT'S INDIVIDUAL AND SHARED BACKUP FILES |
    # --------------------------------------------------
    elif data=="LIST-MY-BACKUPS":
        client_name = get_clientname(client_ip, serving_port, conn_tracker)
        if not client_name:
            return conn, False, conn_tracker  # bye client
        client_loggedin_status = get_client_loggedin_status(client_ip, serving_port, client_name, conn_tracker)
        if not client_loggedin_status:
            return conn, False, conn_tracker  # bye client
        print "[+][" + now() + "] Client %s wants to know every directory we have backed up so far." %(client_name)
        
        individual_backup_dirs = get_individual_backup_dirs(client_name)
        shared_backup_dirs = get_shared_backup_dirs(client_name)
        conn = send_in_chunks(conn, individual_backup_dirs)
        conn = send_in_chunks(conn, shared_backup_dirs)
        return conn, True, conn_tracker    # continue connection, this action can be performed in conjunction with others
    # -------------------------------------------
    # REVERT (FILE-FLOW: FROM SERVER TO CLIENT) |
    # -------------------------------------------
    elif data=="REVERT":
        client_name = get_clientname(client_ip, serving_port, conn_tracker)
        if not client_name:
            return conn, False, conn_tracker  # bye client
        client_loggedin_status = get_client_loggedin_status(client_ip, serving_port, client_name, conn_tracker)
        if not client_loggedin_status:
            return conn, False, conn_tracker  # bye client
        print "[+][" + now() + "] Client %s wants to revert his local files to another point in time." %(client_name)

        conn, chosen_backup_directory = read_in_chunks(conn, client_name)
        serverside_individual_dirname = individual_backup_files_dir + os.sep + client_name + "@"
        
        all_backup_dirs = sorted(os.listdir(individual_backup_files_dir))
        client_backup_dirs = []
        for client_backup in reversed(all_backup_dirs):
            server_backup_file = individual_backup_files_dir + os.sep + client_backup
            if serverside_individual_dirname in server_backup_file:
                client_backup_dirs.append(client_backup)

        restore_list = []
        checkpoint_found_flag = False
        for client_backup_directory in client_backup_dirs:
            print client_backup_directory
            print (client_name + "@" + chosen_backup_directory)
            restore_list.append(client_backup_directory)
            if (client_name + "@" + chosen_backup_directory)==client_backup_directory:
                checkpoint_found_flag = True
                break
        if not checkpoint_found_flag:
            print "[!][" + now() + "] The checkpoint client %s sent us isn't available. This shouldn't be possible if the client doesn't tamper with the client application" %(client_name)
            return conn, False, conn_tracker    # bye client

        clientside_individual_dirname = "myfiles"
        serverside_individual_dirname = individual_files_dir + os.sep + client_name

        file_structure_list = []
        for client_backup_directory in restore_list:
            backup_individual_dirname = individual_backup_files_dir + os.sep + client_backup_directory
            file_structure = fs_server2client(backup_individual_dirname, clientside_individual_dirname)
            file_structure_list.append(file_structure)

        conn = send_in_chunks(conn, file_structure_list)
        conn = server_send_ok(conn, client_name)
        return conn, False, conn_tracker    # bye client
    # --------------------------------------------------
    # REVERT-SHARED (FILE-FLOW: FROM SERVER TO CLIENT) |
    # --------------------------------------------------
    elif data=="REVERT-SHARED":
        client_name = get_clientname(client_ip, serving_port, conn_tracker)
        if not client_name:
            return conn, False, conn_tracker  # bye client
        client_loggedin_status = get_client_loggedin_status(client_ip, serving_port, client_name, conn_tracker)
        if not client_loggedin_status:
            return conn, False, conn_tracker  # bye client
        print "[+][" + now() + "] Client %s wants to revert his local files to another point in time." %(client_name)

        conn, chosen_backup_directory = read_in_chunks(conn, client_name)
        client_names_list = chosen_backup_directory.split("@",1)[0].split("-")
        client_names_repr = "-".join(client_names_list)
        shared_backup_dirs = reversed(sorted(get_shared_backup_dirs(client_name)))

        restore_list = []
        checkpoint_found_flag = False
        for shared_backup_directory in shared_backup_dirs:
            restore_list.append(shared_backup_directory)
            if chosen_backup_directory==shared_backup_directory:
                checkpoint_found_flag = True
                break
        if not checkpoint_found_flag:
            print "[!][" + now() + "] The checkpoint client %s sent us isn't available. This shouldn't be possible if the client doesn't tamper with the client application" %(client_name)
            return conn, False, conn_tracker    # bye client
        clientside_shared_dirname = "mysharedfiles" + os.sep + client_names_repr
        file_structure_list = []
        for shared_backup_directory in restore_list:
            backup_shared_dirname = shared_backup_files_dir + os.sep + shared_backup_directory
            file_structure = fs_server2client(backup_shared_dirname, clientside_shared_dirname, sharedfile_username=client_name)
            file_structure_list.append(file_structure)

        conn = send_in_chunks(conn, file_structure_list)
        conn = server_send_ok(conn, client_name)
        return conn, False, conn_tracker    # bye client
    # --------------------------------------------------------
    # DELETE-FILE (appliable to individual files and backups |
    # --------------------------------------------------------
    elif data=="DELETE-FILE":
        client_name = get_clientname(client_ip, serving_port, conn_tracker)
        if not client_name:
            return conn, False, conn_tracker  # bye client
        client_loggedin_status = get_client_loggedin_status(client_ip, serving_port, client_name, conn_tracker)
        if not client_loggedin_status:
            return conn, False, conn_tracker  # bye client
        print "[+][" + now() + "] Client %s wants to delete a local file or dir in here (individual files)." %(client_name)
        clientside_path = conn.read()
        clientside_individual_dirname = "myfiles"
        serverside_individual_dirname = individual_files_dir + os.sep + client_name
        serverside_path = clientside_path.replace(clientside_individual_dirname,serverside_individual_dirname, 1)  # replace only first occurence
        if sandbox_escaped(serverside_path, serverside_individual_dirname, conn, client_name):
            return conn, False, conn_tracker    # bye client
        if os.path.isdir(serverside_path):
            cmd = "rm -r " + serverside_path    # directly remove the files from the server
            subprocess.check_call(cmd.split(), stdout=open(os.devnull), stderr=subprocess.STDOUT)
        elif os.path.isfile(serverside_path + ".encrypted"):
            cmd1 = "rm -r " + serverside_path + ".encrypted"    # directly remove the files from the server
            cmd2 = "rm -r " + serverside_path + ".key.encrypted"   # directly remove the files from the server
            cmd3 = "rm -r " + serverside_path + ".sig"   # directly remove the files from the server
            subprocess.check_call(cmd1.split(), stdout=open(os.devnull), stderr=subprocess.STDOUT)
            subprocess.check_call(cmd2.split(), stdout=open(os.devnull), stderr=subprocess.STDOUT)
            subprocess.check_call(cmd3.split(), stdout=open(os.devnull), stderr=subprocess.STDOUT)
        conn = server_send_ok(conn, client_name)
        return conn, False, conn_tracker    # bye client

def threaded_clienthandler(client_ip, serving_port, serving_socket, initial_ssl_context):
    new_conn = initial_ssl_context.wrap_socket(serving_socket, server_side=True, do_handshake_on_connect=True)
    open_sockets.append(new_conn)
    try:
        deal_with_client(new_conn, client_ip, serving_port)
    # clean up: close connection socket if open and leave
    except KeyboardInterrupt:
        if new_conn in open_sockets: server_close_connection_socket(new_conn, serving_port)
        print "[!][" + now() + "] CTRL-C: Server shutting down..."
        exit()
    except ssl.SSLError as err:
        print "[!][" + now() + "] Client sent a message that could not be decrypted. Closing connection. Error code: %s" %(repr(err))
    # normal behavior: close connection socket
    if new_conn in open_sockets: server_close_connection_socket(new_conn, serving_port)
    thread_semaphore.release()

def wait_for_clients(main_server_socket, initial_ssl_context):
    # ensuring robustness in server shutdowns
    try:
        serving_socket, serving_info = main_server_socket.accept()
        client_ip = serving_info[0]
        serving_port = serving_info[1]
        thread_semaphore.acquire()
    # clean up: close all current connections and leave
    except KeyboardInterrupt:
        for open_client_conn in open_sockets:
            server_close_connection_socket(open_client_conn, serving_port)
        print "[!][" + now() + "] CTRL-C: Server shutting down..."
        exit()
    #threaded_clienthandler(client_ip, serving_port, serving_socket, initial_ssl_context) # debugging without multi-threading 
    # deal with new connection by creating a new thread
    handler_thread = threading.Thread(target=threaded_clienthandler, args=(client_ip, serving_port, serving_socket, initial_ssl_context))
    handler_thread.start()

def server():
    simple_banner = "###################### SIRS-SERVER ######################"
    print simple_banner

    HOST = ""
    PORT = 1337

    # TLS VERSION USED: TLSv1.2
    # the purpose of this ssl context is to initiate a connection with the client.
    # we will not be able to fully authenticate the client just yet
    initial_ssl_context = ssl.SSLContext(ssl.PROTOCOL_TLSv1_2)
    # load necessary files to create a TLS connection (server certificate and private key)
    initial_ssl_context.load_cert_chain(certfile="server/sirs-server.crt", keyfile="server/sirs-server.key")
    # we have a fake domain name in the client certificate, but we can't verify it yet because we don't know
    # the client's defined hostname yet, neither do we have the client's certificate yet. We need to uncheck
    # this option and create a One-way TLS connection for now
    initial_ssl_context.check_hostname = False
    # we do not require a certificate from the client just yet
    initial_ssl_context.verify_mode = ssl.CERT_NONE


    main_server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    # SO_REUSEADDR is used so the server socket can be reused if needed (for example, if we CTRL-C)
    main_server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    main_server_socket.bind((HOST, PORT))

    main_server_socket.listen(5)    # 5 clients allowed in queue for this socket

    # wait for clients to connect to our server
    while True:
        wait_for_clients(main_server_socket, initial_ssl_context)

clients_dir = "clients"
client_certificates_dir = clients_dir + os.sep + "client_certs"
individual_files_dir = clients_dir + os.sep + "individual_files"
shared_files_dir = clients_dir + os.sep + "shared_files"
individual_backup_files_dir = clients_dir + os.sep + "individual_backups"
shared_backup_files_dir = clients_dir + os.sep + "shared_backups"
mkdir_p(client_certificates_dir)
mkdir_p(individual_files_dir)
mkdir_p(shared_files_dir)
mkdir_p(individual_backup_files_dir)
mkdir_p(shared_backup_files_dir)
OK_MSG = "OK"
NOK_MSG = "NOK"
MAX_THREADS = 4

client_json_filename = clients_dir + os.sep + "clients_info.json"

open_sockets = []

# create clients file if it doesn't exist yet
if not os.path.exists(client_json_filename):
    open(client_json_filename, "a").close()

# populate 'clients' dict from the file (mini dbase)
try:
    json_f = open(client_json_filename, "r")
    clients_info = json.loads(json_f.read())
except ValueError:
    clients_info = dict()
json_f.close()

# clean up not needed global variable
del(json_f)

# BOUNDED-SEMAPHORE: limit simultaneous client threads to "MAX_THREADS" (default: 4)
thread_semaphore = threading.BoundedSemaphore(value=MAX_THREADS)

# DANGEROUS VARIABLES FOR MULTI-THREADING: "clients_info", "open_sockets".
# FILE OPERATIONS ARE DANGEROUS IN MULTI-THREADING: CONTROL READ-WRITE OPERATIONS


server()
