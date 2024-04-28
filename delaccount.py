from fido2.hid import CtapHidDevice
from fido2.ctap2 import CredentialManagement, Ctap2, ClientPin
from fido2.ctap2.bio import BioEnrollment


class Ctap2Node:
    def __init__(self, connection):
        super().__init__()
        self.ctap = Ctap2(connection)
        self._info = self.ctap.info
        self.client_pin = ClientPin(self.ctap)
        self._auth_blocked = False
        self._token = None

    def unlock(self, pin):
        permissions = ClientPin.PERMISSION(0)
        if CredentialManagement.is_supported(self._info):
            permissions |= ClientPin.PERMISSION.CREDENTIAL_MGMT
        if BioEnrollment.is_supported(self._info):
            permissions |= ClientPin.PERMISSION.BIO_ENROLL
        self._token = self.client_pin.get_pin_token(pin, permissions)

    def cm(self):
        return CredentialManagement(
            self.ctap,
            pin_uv_protocol=self.client_pin.protocol,
            pin_uv_token=self._token,
        )

    def list_rp(self, cm: CredentialManagement):
        rps = cm.enumerate_rps()
        print(f'rps: {rps}')


def main(pin):
    devices = list(CtapHidDevice.list_devices())
    device = Ctap2Node(devices[0])
    device.unlock(pin)
    cm = device.cm()

    # list rp
    enumerate_rps = cm.enumerate_rps()
    print(f'\n\nenumerate_rps: {enumerate_rps}')
    for index, rp in enumerate(enumerate_rps):
        print(f'  {index}:{rp[CredentialManagement.RESULT.RP]["id"]}')
    index = input('select rp:').strip()
    select_rp = enumerate_rps[int(index)]

    # list cred
    enumerate_creds = cm.enumerate_creds(rp_id_hash=select_rp[CredentialManagement.RESULT.RP.RP_ID_HASH])
    print(f"\n\nenumerate_creds: {enumerate_creds}")
    for index, cred in enumerate(enumerate_creds):
        print(f'  {index}:{cred[CredentialManagement.RESULT.USER]["name"]}')
    index = input('select cred:').strip()
    select_cred = enumerate_creds[int(index)]

    # delete cred
    cm.delete_cred(select_cred[CredentialManagement.RESULT.CREDENTIAL_ID])


if __name__ == '__main__':
    main('00000') # set pin
