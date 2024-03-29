#!/bin/bash
echo -e "\033[0;32mDeploying updates to GitHub...\033[0m"
# Build the project.
hugo -t geekblog
cd public
git checkout master
git add -A
# Commit changes.
msg="Updating re-dojo `date`"
if [ $# -eq 1 ]
  then msg="$1"
fi
git commit -m "$msg"
git push
cd ..
