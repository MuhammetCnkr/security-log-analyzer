def squares_lazy(limit: int):
    for number in range(limit):
        yield number * number

print(squares_lazy(8))
