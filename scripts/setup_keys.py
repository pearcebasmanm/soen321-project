"""Script to setup demo keys"""
from api.crypto import generate_demo_keys


def main():
    """This will Generate PKCS8/PEM keys"""
    generate_demo_keys()
    print("Demo keys generated in ./keys")


if __name__ == "__main__":
    main()