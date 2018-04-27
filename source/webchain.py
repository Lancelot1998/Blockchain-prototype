# -*- coding: utf-8 -*-
"""
    webchain
    ~~~~~~~~

    a frontend based on flask which helps users to submit transactions to the blockchain

    :author: hank
"""

from flask import Flask, request
from source.blockchain import Transaction, TransInput, TransOutput

app = Flask(__name__)


@app.route("/transaction", methods=['GET', 'POST'])
def transaction():
    if request.method == 'GET':
        return r'<!DOCTYPE html><html><body><form action="/transaction" method=POST>From:<br><input type="text" ' \
               r'name="from" value=""><br>To:<br><input type="text" name="to" value=""><br>Amount:<br><input ' \
               r'type="text" name="amount" value="" pattern="+[0-9]"><br>Private Key:<br><textarea rows="4" ' \
               r'cols="20" name="prikey" value=""></textarea><br>Input(TxID,index;):<br><textarea rows="4" cols="20" ' \
               r'name="input" value=""></textarea><br><input type="submit" value="Submit"></form> </body></html>'
    else:
        issuer = request.form['from']
        receiver = request.form['to']
        amount = request.form['amount']
        prikey = request.form['prikey']
        ipt = request.form['input']


if __name__ == "__main__":
    app.run()