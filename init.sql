-- Create the 'com_ltd_protected' database if it does not already exist
CREATE DATABASE IF NOT EXISTS com_ltd_protected;

-- Create the 'com_ltd_vulnerable' database if it does not already exist
CREATE DATABASE IF NOT EXISTS com_ltd_vulnerable;

-- Create a user 'backendU_p' for the protected backend, if it does not already exist
CREATE USER IF NOT EXISTS 'backendU_p'@'%' IDENTIFIED BY 'admin';

-- Create a user 'backendU_v' for the vulnerable backend, if it does not already exist
CREATE USER IF NOT EXISTS 'backendU_v'@'%' IDENTIFIED BY 'admin';

-- Grant all privileges to 'backendU_p' on 'com_ltd_protected' database
GRANT ALL PRIVILEGES ON com_ltd_protected.* TO 'backendU_p'@'%';

-- Grant all privileges to 'backendU_v' on 'com_ltd_vulnerable' database
GRANT ALL PRIVILEGES ON com_ltd_vulnerable.* TO 'backendU_v'@'%';

-- Apply the changes and refresh the privileges to take effect immediately
FLUSH PRIVILEGES;
