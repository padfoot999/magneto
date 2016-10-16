#!/usr/bin/python -tt
# -*- coding: utf-8 -*-

__description__ = 'Handle all file open, read and process operations'

import collections
import codecs

import os

import logging
logger = logging.getLogger('root')

import argparse

TRANSLATION_DICT = {
    'ホスト名:': 'Host Name:',
    'OS 名:': 'OS Name:',
    'OS バージョン:': 'OS Version:',
    'ビルド': 'Build',
    'OS 製造元:': 'OS Manufacturer:',
    'OS 構成:': 'OS Configuration:',
    'スタンドアロン ワークステーション': 'Stand-alone workstation',
    'OS Buildの種類:': 'OS Build Type:',
    '登録されている所有者:': 'Registered Owner:',
    '登録されている組織:': 'Registered Organization:',
    'プロダクト ID:': 'Product ID:',
    '最初のインストール日付:': 'Original Install Date:',
    'システム起動時間:': 'System Boot Time:',
    'システム製造元:': 'System Manufacturer:',
    'システム モデル:': 'System Model:',
    'システムの種類:': 'System Type:',
    'プロセッサ:': 'Processor(s):',
    'プロセッサインストール済みです。': 'Processor(s) Installed.',
    'Windows ディレクトリ:': 'Windows Directory:',
    'システム ディレクトリ:': 'System Directory:',
    '起動デバイス:': 'Boot Device:',
    'システム ロケール:': 'System Locale:',
    '日本語': 'Japanese',
    '入力ロケール:': 'Input Locale:',
    'タイム ゾーン:': 'Time Zone:',
    'バンコク、ハノイ、ジャカルタ': 'Bangkok, Hanoi, Jakarta',
    '物理メモリの合計:': 'Total Physical Memory:',
    '利用できる物理メモリ:': 'Available Physical Memory:',
    '仮想メモリ: 最大サイズ:': 'Virtual Memory: Max Size:',
    '仮想メモリ: 利用可能:': 'Virtual Memory: Available:',
    '仮想メモリ: 使用中:': 'Virtual Memory: In Use:',
    'ページ ファイルの場所:': 'Page File Location(s):',
    'ドメイン:': 'Domain:',
    'ログオン サーバー:': 'Logon Server:',
    'ホットフィックス:': 'Hotfix(s):',
    'ホットフィックスがインストールされています。': 'Hotfix(s) Installed.',
    'ネットワーク カード:': 'Network Card(s):',
    'インストール済みです。': 'Installed.',
    '接続名:': 'Connection Name:',
    'DHCP が有効:': 'DHCP Enabled:',
    'はい': 'Yes',
    'いいえ': 'No',
    'DHCP サーバー:': 'DHCP Server:',
    'IP アドレス': 'IP address(es)',
    '状態:': 'Status:',
    'メディアは接続されていません': 'Media disconnected',
    'Hyper-V の要件:': 'Hyper-V Requirements:',
    'VM モニター モード拡張機能:': 'VM Monitor Mode Extensions:',
    'ファームウェアで仮想化が有効になっています:': 'Virtualization Enabled In Firmware:',
    '第 2 レベルのアドレス変換:': 'Second Level Address Translation:',
    'データ実行防止が使用できます:': 'Data Execution Prevention Available:',
    'イメージ名': 'Image Name',
    'サービス': 'Services',
    'イーサネット':'Ethernet',
    'ドライバー管理により、デバイス インスタンス':'The driver management, device instance',
    'をインストールするプロセスを次の状態で終了しました':'The install process failed with the following status',
    'ドライバー パッケージのインストールに成功しました。':''
}


#NAME: dequeFile
#INPUT: string filename
#OUTPUT: collections.deque fileBuffer
#DESCRIPTION:
def dequeFile(filename):
    logger.debug("filename is " + str(filename) + "\n")

    #deque is a list-like container which supports fast appends and pops on either end
    fileBuffer = collections.deque()

    with open(filename) as file:
        for line in file:
            #logger.debug("START line is " + line + "\n")
            #remove whitespace
            if line.rstrip():
                line = " ".join(line.split()).strip()
                #logger.debug("After removing whitespace, line is " + line + "\n")

                #split line into individual word for easier string matching
                line = line.split(" ")
                #logger.debug("After splitting, line is " + str(line) + "\n")

                fileBuffer.append(line)
                #print "deque fileBuffer to be returned is " + str(fileBuffer)

    return fileBuffer

#NAME: splitDelimitedLine
#INPUT: collections-deque fileBuffer, char delimiter
#OUTPUT: dictionary insertValue
#DESCRIPTION:
def splitDelimitedLine(list, delimiter):
    logger.debug("delimiter is " + str(delimiter) + "\n")
    logger.debug("list is " + str(list) + "\n")
    columnValue = dict()

    #Join all item in the list and then split them into 2 items, divided by the delimiter
    templist = " ".join(list).split(delimiter, 1)

    tempkey = (templist[0].replace(" ","")).lower()
    logger.debug("tempkey is " + tempkey)

    #strip() will remove leading spaces
    #lower() will change it to lowercase
    tempvalue = (templist[1].strip()).lower()
    logger.debug("tempvalue is " + tempvalue)

    columnValue[tempkey] = tempvalue
    logger.debug("columnValue is " + str(columnValue) + "\n")
    return columnValue



#NAME: translateLine
#INPUT: string
#OUTPUT: NA
#DESCRIPTION: opens and reads filename in python's default ASCII/UTF8 encoding,
# and does translation of elements based on TRANSLATION_DICT.  supports multiple translations per line.
def translateLine(rawLine):
    logger.info("rawLine is " + str(rawLine))

    if any(x in rawLine for x in TRANSLATION_DICT.keys()):
        for key in TRANSLATION_DICT.keys():
            if rawLine.find(key) != -1:
                line = line.replace(key, TRANSLATION_DICT[key])                                
                return line
                break

    try:
        newLine = rawLine.decode('utf-8')        
        return newLine
    except:
        logger.info("Following string is not UTF-8 : " + str(rawLine))
        #unique error string to indicate there's a possible parsing error. Investigator to verify with forensic image for the application name
        return "ERRORERRORERRORERRORERROR"


#NAME: main
#INPUT: NONE
#OUTPUT: NONE
#DESCRIPTION: Provide sample code to show how the functions are called.
def main():
    print "main"
    
if __name__ == '__main__':
	main()