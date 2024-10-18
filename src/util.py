from time import time

start_time = time()


def log(msg: str):
    print(f'{msg} ({int(time() - start_time)}s)')
