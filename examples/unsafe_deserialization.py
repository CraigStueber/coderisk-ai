import pickle

def load_profile(blob: bytes):
    return pickle.loads(blob)  # vulnerable if blob is untrusted
