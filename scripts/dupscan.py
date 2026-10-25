"""Cross-repo duplicate-function scanner (see docs/code-consolidation-backlog.md).

Usage: python3 scripts/dupscan.py [ROOT]   (ROOT = dir holding the sibling repos)
Writes /tmp/dupscan.json and prints a summary.
"""
import ast, hashlib, os, sys, json, collections
ROOT=sys.argv[1] if len(sys.argv)>1 else os.path.abspath(os.path.join(os.path.dirname(__file__),"..",".."))
SKIP={"venv",".venv","node_modules","__pycache__",".git","build","dist"}
class Norm(ast.NodeTransformer):
    def visit_Name(self,n): return ast.copy_location(ast.Name(id="_",ctx=n.ctx),n)
    def visit_arg(self,n): n.arg="_"; n.annotation=None; return n
    def visit_Constant(self,n):
        if isinstance(n.value,str): return ast.copy_location(ast.Constant(value="S"),n)
        return n
exact=collections.defaultdict(list); fuzzy=collections.defaultdict(list)
for repo in sorted(os.listdir(ROOT)):
    rp=os.path.join(ROOT,repo)
    if not os.path.isdir(os.path.join(rp,".git")): continue
    for dp,dns,fns in os.walk(rp):
        dns[:]=[d for d in dns if d not in SKIP]
        if "/tests" in dp or "/test" in dp: continue
        for fn in fns:
            if not fn.endswith(".py") or fn.startswith("test_"): continue
            p=os.path.join(dp,fn)
            try: tree=ast.parse(open(p,encoding="utf-8",errors="ignore").read())
            except Exception: continue
            for node in ast.walk(tree):
                if not isinstance(node,(ast.FunctionDef,ast.AsyncFunctionDef)): continue
                body=node.body
                if body and isinstance(body[0],ast.Expr) and isinstance(getattr(body[0],"value",None),ast.Constant): body=body[1:]
                if not body: continue
                lines=(node.end_lineno or node.lineno)-node.lineno+1
                if lines<6: continue
                mod=ast.Module(body=body,type_ignores=[])
                e=hashlib.sha1(ast.dump(mod).encode()).hexdigest()
                import copy
                f=hashlib.sha1(ast.dump(Norm().visit(copy.deepcopy(mod))).encode()).hexdigest()
                rec=(repo,os.path.relpath(p,ROOT),node.name,node.lineno,lines)
                exact[e].append(rec); fuzzy[f].append(rec)
def groups(d):
    out=[]
    for k,v in d.items():
        files={r[1] for r in v}
        if len(files)>1: out.append(v)
    return sorted(out,key=lambda v:-(v[0][4]*(len(v)-1)))
ex=groups(exact); fz=[g for g in groups(fuzzy) if not any(set(map(tuple,g))==set(map(tuple,x)) for x in ex)]
json.dump({"exact":ex,"fuzzy":fz},open("/tmp/dupscan.json","w"))
def summ(gs,label):
    print(f"## {label}: {len(gs)} groups, {sum(g[0][4]*(len(g)-1) for g in gs)} redundant lines")
summ(ex,"exact"); summ(fz,"structural (renamed vars)")
