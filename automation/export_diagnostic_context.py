#!/usr/bin/env python3
"""Export bounded nonsecret operational coordinates, never desired manifests."""
import argparse,json,os,re,shlex,subprocess,tempfile
from pathlib import Path

SECRET=re.compile(r'(?:PASSWORD|TOKEN|PRIVATE_KEY|ACCESS_KEY|SECRET_KEY)')

def select(outputs,mapping,metadata):
 result={}
 for name,entry in mapping['variables'].items():
  if not re.fullmatch('[A-Z][A-Z0-9_]+',name) or SECRET.search(name):raise ValueError('invalid diagnostic variable')
  if entry.get('metadata'):value=metadata[entry['metadata']]
  else:
   output=outputs[entry['output']]
   if output.get('sensitive') is not False:raise ValueError('diagnostic output must be explicitly non-sensitive')
   value=output['value']
   try:
    for field in entry.get('field','').split('.') if entry.get('field') else []:value=value[field]
   except (KeyError,TypeError):
    if not entry.get('optional'):raise ValueError('required diagnostic field is missing: '+name) from None
    value=''
  if entry.get('transform')=='present':value=value is not None
  if value is None and entry.get('optional'):value=''
  if entry.get('transform')=='join_csv':
   if not isinstance(value,list) or not all(isinstance(x,str) for x in value):raise ValueError('diagnostic CSV requires string list')
   value=','.join(value)
  if isinstance(value,bool):value='true' if value else 'false'
  elif isinstance(value,(int,float)):value=str(value)
  if not isinstance(value,str) or len(value)>2048 or '\n' in value or '\r' in value or '\x00' in value or value.startswith('-----BEGIN'):
   raise ValueError('diagnostic field must be a bounded scalar: '+name)
  result[name]=value
 return result

def write_context(path,values):
 if path.is_symlink():raise ValueError('context target cannot be a symlink')
 path.parent.mkdir(parents=True,exist_ok=True)
 with tempfile.NamedTemporaryFile('w',dir=path.parent,delete=False,encoding='utf-8') as f:
  f.write('# Local nonsecret diagnostic coordinates. Do not commit or use as desired manifests.\n')
  for name,value in values.items():f.write('export '+name+'='+shlex.quote(value)+'\n')
  temporary=Path(f.name)
 temporary.chmod(0o600);temporary.replace(path)

def main():
 repo=Path(__file__).resolve().parents[1]
 mappings=json.loads((repo/'automation/diagnostic-mappings.json').read_text())
 p=argparse.ArgumentParser();p.add_argument('--component',choices=mappings,required=True);p.add_argument('--environment',choices=['dev','prod'],required=True);p.add_argument('--profile',required=True);p.add_argument('--expect-account',required=True);p.add_argument('--output',type=Path,required=True);a=p.parse_args()
 try:
  if not re.fullmatch('[0-9]{12}',a.expect_account):raise ValueError('expected account must have 12 digits')
  account=subprocess.check_output(['aws','--profile',a.profile,'--region','ap-northeast-2','sts','get-caller-identity','--query','Account','--output','text'],text=True).strip()
  if account!=a.expect_account:raise ValueError('diagnostic AWS account differs from expected account')
  env=dict(os.environ);env['AWS_PROFILE']=a.profile;env.pop('TF_LOG',None);env.pop('TF_LOG_PATH',None)
  mapping=mappings[a.component];root=repo/mapping['root'].replace('{environment}',a.environment)
  output=subprocess.run(['terraform','-chdir='+str(root),'output','-json'],env=env,capture_output=True,text=True,check=True)
  values=select(json.loads(output.stdout),mapping,{'environment':a.environment,'account_id':account,'region':'ap-northeast-2'})
  for name,value in values.items():
   if name.endswith(('_ACCOUNT','_ACCOUNT_ID')) and value!=account:raise ValueError('contract account differs from target')
   if name.endswith('_ENVIRONMENT') and value!=a.environment:raise ValueError('contract environment differs from target')
  destination=a.output.resolve()
  if not destination.is_relative_to((repo/'platform/environments'/a.environment).resolve()):raise ValueError('context must stay in selected environment local operations directory')
  write_context(a.output,values)
  print('Diagnostic coordinates refreshed for '+a.environment+'/'+a.component+'; no raw State or credential values saved.')
 except (ValueError,KeyError,OSError,subprocess.CalledProcessError) as error:p.exit(2,'diagnostic context stopped: '+str(error)+'\n')

if __name__=='__main__':main()
