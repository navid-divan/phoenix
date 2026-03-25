class PhoenixError(Exception):
    pass


class InvalidBallotError(PhoenixError):
    pass


class TallyError(PhoenixError):
    pass


class VerificationError(PhoenixError):
    pass


class RegistrationError(PhoenixError):
    pass


class SetupError(PhoenixError):
    pass