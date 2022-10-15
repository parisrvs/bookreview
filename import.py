import csv
import os

from sqlalchemy import create_engine
from sqlalchemy.orm import scoped_session, sessionmaker

engine = create_engine(os.getenv("DATABASE_URL"))
db = scoped_session(sessionmaker(bind=engine))

def main():
    f = open("books.csv")
    reader = csv.DictReader(f)
    for line in reader:
        isbn = line["isbn"]
        title = line["title"]
        author = line["author"]
        year = int(line["year"])        
        db.execute("INSERT INTO books (isbn, title, author, year) VALUES (:isbn, :title, :author, :year)", {"isbn": isbn, "title": title, "author": author, "year": year})
        
    db.commit()    
    f.close()

if __name__ == "__main__":
    main()