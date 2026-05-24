from art import logo

print(logo)
print("Welcome to the secret auction program.")

bids = {}
bidding_finished = False

def find_highest_bidder(bidding_record):
    """Find and return the highest bidder's name and bid amount."""
    highest_bid = 0
    winner = ""
    for bidder in bidding_record:
        bid_amount = bidding_record[bidder]
        if bid_amount > highest_bid:
            highest_bid = bid_amount
            winner = bidder
    print(f"The winner is {winner} with a bid of ${highest_bid}")

while not bidding_finished:
    name = input("What is your name?: ")
    bid = int(input("What's your bid?: $"))
    bids[name] = bid
    
    should_continue = input("Are there any other bidders? Type 'yes' or 'no'.\n").lower()
    if should_continue == "no":
        bidding_finished = True
        find_highest_bidder(bids)
    else:
        print("\n" * 100)