#!/usr/bin/python

import MySQLdb

prompt = "CryptDB-ElG-Demo$ "
tables = {}
table_fields = {}

def setup(cursor):
	cmd = "DROP FUNCTION IF EXISTS prod"
	cursor.execute(cmd)
	cmd = "CREATE FUNCTION prod RETURNS INTEGER SONAME 'edb.so';"
	cursor.execute(cmd)	

def enc(v):
	return v 

def dec(c):
	return c 

def create_rewrite(s):
	#CREATE table tablename (field type, field type...);
	(table, fields) = s.split(" (")
	table = table.replace("CREATE table ", "").strip()
	fields = fields[:fields.index(")")].split(", ")
	field_list = [tuple(f.split(" ")) for f in fields]
	anon_table = "table" + str(len(tables.keys()))
	tables[table] = anon_table
	anon_fields = {}
	for (fname, ftype) in field_list:
		if (ftype != "integer"):
			print "this demo is for ints only"
			return None
		else:
			anon_fname = "field"+str(len(anon_fields))+"ELG"
			anon_fields[fname] = anon_fname
	table_fields[table] = anon_fields
	cmd = "CREATE table " + anon_table + " ("
	for fname in anon_fields.keys():
		cmd += anon_fields[fname] + " binary, " #check if actually bin
	cmd = cmd[:len(cmd)-2] + ");"	
	return cmd

def insert_rewrite(s):
	#INSERT into tablename values();
	s = s.replace("INSERT into ", "")
	(table, vals) = s.split(" values(")
	anon_table = tables[table.strip()]
	vals = vals.replace(");", "").split(",")
	cmd = "INSERT into " + anon_table + " values("
	for val in vals:
		cmd += enc(val) + ", "
	cmd = cmd[:len(cmd)-2] + ");"	
	return cmd	

def select_rewrite(s):
	table = s.split(" ");
	table = table[len(table)-1].replace(";", "")
	anon_table = tables[table]
	#SELECT * from tablename;
	if "SELECT *" in s:
		return "SELECT * from " + anon_table + ";"
	#SELECT field1*field2 from tablename;
	else:
		args = s.split(" ")[1].split("*")
		anon_field = table_fields[table][args[0]]
		val = enc(args[1])
		mod = str(10) #needs to be enc dependent
		return "SELECT prod(" + anon_field + "," + val + \
			"," + mod + ") from " + anon_table+";"

def rewrite(s):
	if ("CREATE" in s):
		return create_rewrite(s)
	elif ("INSERT" in s):
		return insert_rewrite(s)
	elif ("SELECT" in s):
		return select_rewrite(s)
	else:
		print "this command is not supported"
		return None	

if __name__ == '__main__':
	db = MySQLdb.connect(host="localhost", port=3306, user="root", passwd="letmein", db="cryptdbtest")
	cursor = db.cursor()
	setup(cursor)
	try:
		while True:
			cmd_str = raw_input(prompt)
			print "Rewriting ", cmd_str
			cmd_str = rewrite(cmd_str)
			print cmd_str
			if (cmd_str != None):
				cursor.execute(cmd_str)
				print cursor.fetchall()
	except EOFError:
		db.close()
		print "\nGoodbye!"
