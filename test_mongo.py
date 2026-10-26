from pymongo import MongoClient

MONGO_URI = "YOUR_MONGODB_ATLAS_CONNECTION_STRING"

try:
    client = MongoClient(
        MONGO_URI,
        serverSelectionTimeoutMS=5000
    )

    client.admin.command("ping")
    print("MongoDB connected successfully!")

    db = client["vulnlab"]
    print("Database:", db.name)

    client.close()

except Exception as e:
    print("MongoDB connection failed:", e)