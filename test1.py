#!/usr/bin/env python

def f(q):
    print("inside f()")
    q.put([42, None, 'hello'])
