def encode_vote(vote_value: int) -> list:
    return [vote_value]


def decode_vote(plaintext_list: list) -> int:
    if not plaintext_list:
        return 0
    return int(plaintext_list[0])