import os, argparse

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('-n', '--nkeys', type=int, required=False)
    n_keys = parser.parse_args().nkeys

    os.system('python keygen.py -n '+ str(n_keys)) 
    os.system('python sign.py -af')
    os.system('python aggSign.py')
    os.system('python aggVerify.py')

if __name__ == "__main__":
    main()