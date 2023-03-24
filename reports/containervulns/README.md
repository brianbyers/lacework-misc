pip install -r requirements.txt
export LW_PROFILE=<your lacework profile> (can find this in ~/.lacework.toml)
python vulns2excel.py

a new file vulns.xlsx will be generated with the container vulnerability data
