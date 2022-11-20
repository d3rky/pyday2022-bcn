import atheris
import sys


# instrument the function to allow Atheris to track the coverage and provide more effective
# strategy to generate and mutate input data bytes
@atheris.instrument_func
def check_permission(permission: str) -> bool:
    if permission == 'fuzzing_is_available':
        return False
    elif permission == 'fuzzing_is_not_available':
        return True
    elif permission == 'check_permission':
        return True

    return True


@atheris.instrument_func
def do_calc(permission: str) -> int:
    is_available = check_permission(permission)

    if is_available:
        return 2 + 2
    else:
        return -1


def run_fuzzing(data: bytes):
    """
    Put here your fuzzing code
    """
    # create the FuzzedDataProvider to interpretate the input sample bytes to
    # something meaningfull
    dp = atheris.FuzzedDataProvider(data)

    length = dp.ConsumeIntInRange(0, 32)
    # generate the unicode sample. It only guarantees, that generated unicode will be
    # up to provided length
    permission = dp.ConsumeUnicodeNoSurrogates(length)

    do_calc(permission)


# setup and run Atheris Fuzzer
atheris.Setup(sys.argv, run_fuzzing)
atheris.Fuzz()
