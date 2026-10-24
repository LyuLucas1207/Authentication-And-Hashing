from q6_server import Server
from matplotlib import pyplot as plt
import importlib

example = importlib.import_module("a3")


def test_online_pwd_crack(seed, L):
    """Runs the pwd cracking test"""
    
    server = Server(seed, L)
    print(f"The server's password is {server.password}")
    try:
        pwd = example.online_attack(server.check_password)
        if pwd == server.password:
            return 1., f'Done in {server._calls} calls'
        else:
            return 0., 'Wrong password'
    except Exception as e:
        return 0., str(e)


def plot_performance(nreps=100):
    calls_per_L = {i: [] for i in range(5, 11)}
    for seed in range(nreps):
        for L in range(5, 11):
            server = Server(seed, L)
            pwd = example.online_attack(server.check_password)
            if pwd != server.password:
                raise ValueError("Wrong password!")
            calls_per_L[L].append(server._calls)

    x = list(calls_per_L.keys())
    y = list(calls_per_L.values())
    upper = [160*x_val - 250 for x_val in x]

    plt.boxplot(y, positions=x, widths=0.6)
    plt.plot(x, upper, 'r')
    plt.xlabel("Password Length")
    plt.ylabel("Number of Calls to Crack")
    plt.title("Brute-force Cost")
    plt.show()


if __name__ == "__main__":

    plot_performance()

    # for seed in range(11):
    #     L = 5 + (seed % 6)
    #     score, comments = test_online_pwd_crack(seed, L)
    #     print(f"Score={score:.1%}, {comments}")
