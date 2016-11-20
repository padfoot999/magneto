#!/usr/bin/python -tt
__description__ = 'Setup logging to console and file'


import logging
import os

#NAME: setupLogger
#OUTPUT: N/A
#DESCRIPTION: 
def setupLogger(name):
    #Format logging output
    formatter = logging.Formatter('%(asctime)s - %(levelname)s - %(module)s - %(message)s')

    #To print to file
    fileHandler = logging.FileHandler("Incident.log")
    fileHandler.setFormatter(formatter)
    fileHandler.setLevel(logging.INFO)
    
    #To print on screen
    consoleHandler = logging.StreamHandler(os.sys.stdout)
    consoleHandler.setFormatter(formatter)
    consoleHandler.setLevel(logging.DEBUG) #set different level for printing on screen
    
    #Create logger with above handlers
    logger = logging.getLogger(name)    
    logger.setLevel(logging.DEBUG)
    logger.addHandler(consoleHandler) 
    logger.addHandler(fileHandler) 

    return logger

