#!/bin/bash

input=requirements.txt
requirements_out=requirements.txt.new

if [[ "$1" == "help" ]]; then
  echo -e "Usage:\n\tpin_requirements.sh [input_file output_file]\n\nDefaults are requirements.txt and requirements.txt.new respectively."
  exit 0
fi

if [ ! -z "$1" ]; then
  input="$1"
fi

if [ ! -z "$2" ]; then
  requirements_out="$2"
fi

echo "Gathering hashes of requirements..."
tmpout=$(mktemp --directory)
IFS=$'\n'
for entry in $(cat ${input}); do
  if [[ $entry == *"=="* ]]; then
    module=$(echo ${entry} | awk '{print $1}')
    output_file=$(pip3 download ${module} --no-deps --no-binary :all: --dest ${tmpout} 2>&1 | grep -m 1 Saved | head -n 1 | awk '{print $2}')
    hash=$(pip3 hash ${output_file} | grep hash)
    echo "${module} ${hash}"  >> ${requirements_out}
  else
    echo -e "\n${entry}" >> ${requirements_out}
  fi
done
echo "Done. Output written to requirements.txt.new"

