#!/usr/bin/python3

import sys
import pandas as pd

with open(sys.argv[1]) as fd:
    data = eval(fd.read())

texts = pd.DataFrame(data['texts'], columns=["text_idx", "filename", "bytes"])
texts.set_index('text_idx', inplace=True)
funcs = pd.DataFrame(data['functions'], columns=["text_idx", "filename", "bytes", "loaded"])

x = funcs.groupby(["text_idx", "loaded"])['bytes'].agg([sum,len]).unstack()
x.columns = ["%s_%s" % col for col in x.columns.values]

df = texts.merge(x, left_index=True, right_index=True)

df['loaded %'] = (df.bytes - df.sum_0)/df.bytes
print(df)


