from client import send


def send_data(number, phrase):
    response = send(number, phrase)
    # response can be a single string or a tuple (phrase, number5)
    if isinstance(response, (list, tuple)):
        # Print both parts clearly
        print("Response phrase:", response[0])
        if len(response) > 1:
            print(type(response[1]), response[1])
            numero = int(response[1])
            print("Response number*5:", numero*5)
    else:
        print(response)
    return response


if __name__ == "__main__":
    send_data(1, "aaaa")
