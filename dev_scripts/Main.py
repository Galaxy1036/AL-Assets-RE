import os
import sys
import time
import frida


script_name = 'al_hook.js'
package_name = 'sts.al'
MAX_FRIDA_RETRY = 10


def message(message, data):
    print(message, data)


def start_frida_script():
    try:
        device = frida.get_usb_device()

    except Exception as exception:
        sys.exit('[*] Can\'t connect to your device ({}) !'.format(exception.__class__.__name__))

    print('[*] Successfully connected to frida server !')

    pid = device.spawn([package_name])

    retry_count = 0
    process = None

    while not process:
        try:
            process = device.attach(pid)

        except Exception as exception:
            if retry_count == MAX_FRIDA_RETRY:
                sys.exit('[*] Can\'t attach frida to the game ({}) ! Start the frida server on your device'.format(exception.__class__.__name__))

            retry_count += 1
            time.sleep(0.5)

    print('[*] Frida attached !')

    if os.path.isfile(script_name):
        script = process.create_script(open(script_name).read())

    else:
        sys.exit('[*] gl_hook.js script is missing, cannot inject the script !')

    script.on('message', message)
    script.load()
    device.resume(pid)

    print('[*] Script injected !')


if __name__ == '__main__':
    start_frida_script()
    sys.stdin.read()
