make; 
sudo make install; 
rm -r /var/lib/shadow-mysql/*; 
mysql -u root -pletmein -e "drop database cryptdbtest"; 
mysql -u root -pletmein -e "create database cryptdbtest";
mysql -u root -pletmein -e  "drop database cryptdbtest_control"; mysql -u root -pletmein -e "create database cryptdbtest_control"; 
obj/main/cdb_test /var/lib/shadow-mysql
