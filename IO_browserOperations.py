import sqlite3
from pandas import DataFrame
def chrome_history(file):
	db = sqlite3.connect(file)
	cursor = db.cursor()
	statement = "SELECT urls.url, urls.title, urls.last_visit_time FROM urls;"
	cursor.execute(statement)
	results = DataFrame(cursor.fetchall())
	return results