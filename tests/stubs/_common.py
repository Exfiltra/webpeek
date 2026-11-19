import sys, os, json, time
A = sys.argv[1:]
def arg(flag, default=None):
    for i, a in enumerate(A):
        if a == flag and i + 1 < len(A): return A[i+1]
        if a.startswith(flag + "="): return a.split("=", 1)[1]
    return default
def w(path, text):
    os.makedirs(os.path.dirname(path) or ".", exist_ok=True)
    open(path, "w").write(text)
