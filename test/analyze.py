#!/usr/bin/python3

import sys
import pandas as pd

pd.set_option('display.max_rows', None)
pd.set_option('display.max_columns', None)
pd.set_option('display.width', None)
pd.set_option('display.max_colwidth', -1)

with open(sys.argv[1]) as fd:
    data = eval(fd.read())

texts = pd.DataFrame(data['texts'], columns=["text_idx", "filename", "bytes"])
texts.set_index('text_idx', inplace=True)
funcs = pd.DataFrame(data['functions'], columns=["text_idx", "name", "bytes", "offset", "loaded", "essential", "restore_time"])

x = funcs.groupby(["text_idx", "loaded"])['bytes'].agg([sum,len]).unstack()
x.columns = ["%s_%s" % col for col in x.columns.values]

df = texts.merge(x, left_index=True, right_index=True)

df['loaded %'] = (df.bytes - df.sum_False)/df.bytes
print(df)

print((sum(df.bytes) - sum(df.sum_False))/ sum(df.bytes))

funcs['bytes_per_ns']= funcs.bytes / funcs.restore_time

print(funcs.query(expr="loaded==True and essential==False and bytes >= 16")[['name', 'restore_time', "bytes", 'bytes_per_ns']])

