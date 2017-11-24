#!/usr/bin/python -tt
# -*- coding: utf-8 -*-

__description__ = 'Handle all file open, read and process operations'

import collections
import codecs

import io
import chardet

import os

import logging
logger = logging.getLogger('root')

import argparse

TRANSLATION_DICT = {
    u'ホスト名:': 'Host Name:',
    u'名:': 'Name:',
    u'バージョン:': 'Version:',
    u'ビルド': 'Build',
    u'製造元:': 'Manufacturer:',
    u'構成:': 'Configuration:',
    u'スタンドアロン ワークステーション': 'Stand-alone workstation',
    u'ビルドの種類:': 'Build Type:',
    u'登録されている所有者:': 'Registered Owner:',
    u'登録されている組織:': 'Registered Organization:',
    u'プロダクト': 'Product',
    u'最初のインストール日付:': 'Original Install Date:',
    u'システム起動時間:': 'System Boot Time:',
    u'システム製造元:': 'System Manufacturer:',
    u'モデル:': 'Model:',
    u'システムの種類:': 'System Type:',
    u'プロセッサ:': 'Processor(s):',
    u'プロセッサインストール済みです。': 'Processor(s) Installed.',
    u'ディレクトリ:': 'Directory:',
    u'システム': 'System',
    u'起動デバイス:': 'Boot Device:',
    u'ロケール:': 'Locale:',
    u'入力ロケール:': 'Input Locale:',
    u'タイム': 'Time',
    u'ゾーン:': 'Zone:',
    u'バンコク、ハノイ、ジャカルタ': 'Bangkok, Hanoi, Jakarta',
    u'物理メモリの合計:': 'Total Physical Memory:',
    u'利用できる物理メモリ:': 'Available Physical Memory:',
    u'仮想メモリ:' : 'Virtual Memory:',
    u'最大サイズ:': 'Max Size:',
    u'利用可能:': 'Available:',
    u'使用中:': 'In Use:',
    u'ページ': 'Page',
    u'ファイルの場所:': 'File Location(s):',
    u'ドメイン:': 'Domain:',
    u'ログオン': 'Logon',
    u'サーバー:': 'Server:',
    u'ホットフィックス:': 'Hotfix(s):',
    u'ホットフィックスがインストールされています。': 'Hotfix(s) Installed.',
    u'ネットワーク': 'Network',
    u'カード:': 'Card(s):',
    u'インストール済みです。': 'Installed.',
    u'接続名:': 'Connection Name:',
    u'が有効:': 'Enabled:',
    u'はい': 'Yes',
    u'いいえ': 'No',
    u'サーバー:': 'Server:',
    u'アドレス': 'address(es)',
    u'状態:': 'Status:',
    u'メディアは接続されていません': 'Media disconnected',
    u'の要件:': 'Requirements:',
    u'モニター': 'Monitor', 
    u'モード拡張機能:': 'Mode Extensions:',
    u'ファームウェアで仮想化が有効になっています:': 'Virtualization Enabled In Firmware:',
    u'第':'',
    u'レベルのアドレス変換:': 'Second Level Address Translation:',
    u'データ実行防止が使用できます:': 'Data Execution Prevention Available:',
    u'イメージ名': 'Image Name',
    u'サービス': 'Services',
    u'イーサネット':'Ethernet',
    u'ドライバー管理により、デバイス インスタンス':'The driver management, device instance',
    u'をインストールするプロセスを次の状態で終了しました':'The install process failed with the following status',
    u'ドライバー パッケージのインストールに成功しました。':'',
    u'アクティブな接続': 'Active Connections',
    u'プロトコル': 'Proto',
    u'ローカル': 'Local',
    u'アドレス': 'Address',
    u'外部アドレス': 'Foreign Address',
    u'状態': 'State'
}

ILLEGAL_SENTENCES = [['The', 'requested', 'operation', 'requires', 'elevation.']]

#NAME: dequeFile
#INPUT: string line
#OUTPUT: string line
#DESCRIPTION: Cleans lines to make sure that headings are standardized
def cleanline(line):
    if line[0:2] == ['2', 'Second']:
        line.remove('2')
    return line

#NAME: dequeFile
#INPUT: string filename
#OUTPUT: collections.deque fileBuffer
#DESCRIPTION:
def dequeFile(filename):
    logger.debug("filename is " + str(filename) + "\n")

    #deque is a list-like container which supports fast appends and pops on either end
    fileBuffer = collections.deque()

    rawdata = open(filename, "r").read()
    result = chardet.detect(rawdata)
    charenc = result['encoding']
    if result['confidence'] >= 0.75:
        charenc = result['encoding']
    else:
    #default encoding for texts with language
        charenc = 'SHIFT-JIS'
    try: 
        f = codecs.open(filename, "r", charenc)
        f.read()
    except:
        charenc = result['encoding']
    #Still able to use utf-8 to read when original file is encoded with utf-8-sig
    if charenc == "UTF-8-SIG": 
        charenc = "UTF-8"

    with io.open(filename, "r", encoding=charenc) as f:
        for line in f:
            #remove whitespace
            if line.rstrip():
                #split line into individual word for easier string matching
                line = " ".join(line.split()).strip()
                line = line.split(" ")
                line = translateLine(line)
                #Translated line contains spaces
                line = " ".join(line).strip()
                line = line.split(" ")
                line = cleanline(line)
                if line not in ILLEGAL_SENTENCES:
                    fileBuffer.append(line)
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
    if any(x in rawLine for x in TRANSLATION_DICT.keys()):
        logger.debug("Translating")
        for key in TRANSLATION_DICT.keys():
            if key in rawLine:
                rawLine = [line.replace(key, TRANSLATION_DICT[key]) for line in rawLine]
        return rawLine
    else:
        return rawLine


    
if __name__ == '__main__':
	pass