#!/bin/bash
cat $1 | python -m json.tool  >> /dev/null && exit 0 || echo "NOT valid JSON"; exit 1
