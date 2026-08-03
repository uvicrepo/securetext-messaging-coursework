import json
from securetext_salted import hash_password

INPUT_FILE = "../../users.json"
OUTPUT_FILE = "test_users.json" # For testing, change to = INPUT_FILE

with open(INPUT_FILE, 'r') as f:
    users = json.load(f)

for  username, data in users.items():
    new_salt, new_password = hash_password(data["password"])
    users[username] = {
        "password": new_password,
        "salt": new_salt,
        "created_at": data["created_at"],
        "reset_question": data["reset_question"],
        "reset_answer": data["reset_answer"]
    }

with open(INPUT_FILE, 'w') as f:
    json.dump(users, f, indent=4)

print(f"\nDone. {INPUT_FILE} is now a salty dog.")