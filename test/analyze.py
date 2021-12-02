#!/usr/bin/python3

import sys
import pandas as pd

def main():
    pd.set_option('display.max_rows', None)
    pd.set_option('display.max_columns', None)
    pd.set_option('display.width', None)
    pd.set_option('display.max_colwidth', None)


    with open(sys.argv[1]) as fd:
        data = fd.read().split("\x01")
        for datum in data:
            if not datum: continue
            analyze(eval(datum))


def analyze(data):
    texts = pd.DataFrame(data['texts'], columns=["text_idx", "filename", "bytes"])
    texts.set_index('text_idx', inplace=True)
    funcs = pd.DataFrame(data['functions'], columns=["text_idx", "name", "bytes", "offset", "loaded", "essential", "restore_time"])

    x = funcs.groupby(["text_idx", "loaded"])['bytes'].agg([sum,len]).unstack()
    x.columns = ["%s_%s" % col for col in x.columns.values]

    df = texts.merge(x, left_index=True, right_index=True)
    df.fillna(0, inplace=True)

    df['sum_Total'] = df.sum_False + df.sum_True
    df['len_Total'] = df.len_False + df.len_True


    df['loaded %'] = (df.bytes - df.sum_False)/df.bytes
    df['wipeable %'] = (df.sum_True + df.sum_False)/df.bytes

    print(df)

    print("Total bytes loaded (%):",   (sum(df.bytes) - sum(df.sum_False))/ sum(df.bytes))
    print("Wipeable bytes loaded (%):", (sum(df.sum_True)/sum(df.sum_Total)))
    print("Wipeable funcs loaded (%):", (sum(df.len_True)/sum(df.len_Total)))
    print("Restore (count/ms):", sum(df.len_True), sum(funcs.restore_time)/1e6)

    

    funcs['bytes_per_ns']= funcs.bytes / funcs.restore_time

    # print(funcs.query(expr="loaded==True and essential==False and bytes >= 16")[['name', 'restore_time', "bytes", 'bytes_per_ns']])


if __name__ == "__main__":
    main()
