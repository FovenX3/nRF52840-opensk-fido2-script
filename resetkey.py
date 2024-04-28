from fido2.hid import CtapHidDevice
from fido2.ctap2 import Ctap2


def reset():
    devices = list(CtapHidDevice.list_devices())
    ctap2 = Ctap2(devices[0])
    ctap2.reset()


if __name__ == '__main__':
    reset()
