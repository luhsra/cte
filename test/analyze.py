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
            print("---")


def analyze(data):
    if 'texts' not in data:
        print("Loaded KiB", (data['text_bytes'] - data['cur_wipe_bytes']) / 1024)
        print("Loaded Wipeable KiB", (data['function_bytes'] - data['cur_wipe_bytes']) / 1024)

        print("Total bytes loaded (%):",   (data['text_bytes'] - data['cur_wipe_bytes']) / data['text_bytes'])
        print("Wipeable bytes loaded (%):", (data['function_bytes'] - data['cur_wipe_bytes']) / data['function_bytes'])
        print("Wipeable funcs loaded (%):", (data['function_count'] - data['cur_wipe_count']) / data['function_count'])
        return
    texts = pd.DataFrame(data['texts'], columns=["text_idx", "filename", "bytes"])
    texts.set_index('text_idx', inplace=True)
    funcs = pd.DataFrame(data['functions'], columns=["text_idx", "name", "bytes", "offset", "state", "essential", "restore_time", "loadable"])
    funcs['loaded'] = funcs.state == 1 # CTE_LOAD

    x = funcs.groupby(["text_idx", "loaded"])['bytes'].agg([sum,len]).unstack()
    x.columns = ["%s_%s" % col for col in x.columns.values]

    df = texts.merge(x, left_index=True, right_index=True)
    df.fillna(0, inplace=True)

    df['sum_Total'] = df.sum_False + df.sum_True
    df['len_Total'] = df.len_False + df.len_True

    df['loaded %'] = (df.bytes - df.sum_False)/df.bytes
    df['wipeable %'] = (df.sum_True + df.sum_False)/df.bytes
    df['unwipeable'] = df.bytes - df.sum_Total

    print(df)

    print("Total bytes loaded (%):",   (sum(df.bytes) - sum(df.sum_False))/ sum(df.bytes))
    print("Wipeable bytes loaded (%):", (sum(df.sum_True)/sum(df.sum_Total)))
    print("Wipeable funcs loaded (%):", (sum(df.len_True)/sum(df.len_Total)), sum(df.len_True))
    print("Restore (count):", sum(df.len_True), data['restore_count'], data['restore_time']/1e6)

    print(data.keys())
    
    funcs['memfunc'] = funcs.name.map(lambda x: x.startswith('__mem'))

    x = funcs[(~funcs.loaded) & (~funcs.memfunc)][['text_idx', 'name', 'bytes']]
    # print(x.join(texts.reset_index()[['text_idx', 'filename']], on='text_idx',lsuffix="L"))
    print(len(x))
    print(sum(x.bytes))


if __name__ == "__main__":
    main()
