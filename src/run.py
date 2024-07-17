from send_in_fragments.send import send_in_fragments


if __name__ == "__main__":
    print("Sending...")
    payload = b"A" * 0x100
    payload += b"B" * 0x50
    payload += b"\n"
    # payload = b"Hello TCP.\n"
    send_in_fragments("192.168.219.10", 1234, payload)
    # send_in_fragments("127.0.0.1", 4444, payload)

