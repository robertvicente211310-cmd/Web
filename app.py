import os, uuid, secrets, hashlib, hmac
from datetime import datetime, timezone, timedelta
from functools import wraps
import jwt
from flask import Flask, request, jsonify, render_template, session, redirect, url_for
from flask_cors import CORS
from dotenv import load_dotenv
from db import init_db, db_conn

load_dotenv()
app=Flask(__name__)
app.secret_key=os.getenv("SECRET_KEY","dev-only-change-me")
app.config.update(SESSION_COOKIE_HTTPONLY=True, SESSION_COOKIE_SAMESITE="Lax", SESSION_COOKIE_SECURE=os.getenv("RENDER")=="true")
origins=[x.strip() for x in os.getenv("ALLOWED_ORIGINS","").split(",") if x.strip()]
CORS(app, resources={r"/api/*":{"origins":origins or "*"}}, supports_credentials=False)
init_db()

def now(): return datetime.now(timezone.utc).isoformat()
def uid(): return str(uuid.uuid4())
def pw_hash(password):
    salt=secrets.token_bytes(16)
    digest=hashlib.pbkdf2_hmac("sha256",password.encode(),salt,260000)
    return salt.hex()+":"+digest.hex()
def pw_ok(password, stored):
    try:
        salt, digest=stored.split(":")
        check=hashlib.pbkdf2_hmac("sha256",password.encode(),bytes.fromhex(salt),260000).hex()
        return hmac.compare_digest(check,digest)
    except Exception: return False
def token_for(user):
    return jwt.encode({"sub":user["id"],"role":user["role"],"exp":datetime.now(timezone.utc)+timedelta(hours=24)},app.secret_key,algorithm="HS256")
def auth(required_role=None):
    def deco(fn):
        @wraps(fn)
        def wrapped(*args,**kwargs):
            header=request.headers.get("Authorization","")
            try:
                payload=jwt.decode(header.removeprefix("Bearer ").strip(),app.secret_key,algorithms=["HS256"])
                with db_conn() as c:
                    row=c.execute("SELECT id,username,role,credits,active FROM users WHERE id=?",(payload["sub"],)).fetchone()
                if not row or not row[4]: raise ValueError()
                user={"id":row[0],"username":row[1],"role":row[2],"credits":row[3]}
                if required_role and user["role"]!=required_role: return jsonify(error="No autorizado"),403
                request.current_user=user
            except Exception: return jsonify(error="Sesión no válida"),401
            return fn(*args,**kwargs)
        return wrapped
    return deco
def rowdict(row, keys): return dict(zip(keys,row)) if row else None
def admin_user():
    username=os.getenv("ADMIN_USERNAME","admin")
    password=os.getenv("ADMIN_PASSWORD","")
    if not password: return
    with db_conn() as c:
        found=c.execute("SELECT id FROM users WHERE username=?",(username,)).fetchone()
        if not found:
            c.execute("INSERT INTO users(id,username,password_hash,role,credits,active,created_at) VALUES(?,?,?,?,?,?,?)",(uid(),username,pw_hash(password),"admin",0,1,now()))
            c.commit()
admin_user()

@app.get("/health")
def health(): return jsonify(status="ok",service="nexora-admin-api")

@app.get("/")
def dashboard():
    if not session.get("admin_token"): return render_template("login.html")
    return render_template("admin.html")

@app.post("/admin/login")
def admin_login():
    data=request.get_json(silent=True) or request.form
    username=data.get("username",""); password=data.get("password","")
    with db_conn() as c:
        row=c.execute("SELECT id,username,password_hash,role,credits,active FROM users WHERE username=?",(username,)).fetchone()
    if not row or row[3]!="admin" or not row[5] or not pw_ok(password,row[2]):
        return (jsonify(error="Credenciales incorrectas") if request.is_json else render_template("login.html",error="Credenciales incorrectas")),401
    tok=token_for({"id":row[0],"role":row[3]})
    if request.is_json: return jsonify(token=tok,username=row[1])
    session["admin_token"]=tok
    return redirect("/")
@app.post("/admin/logout")
def admin_logout():
    session.clear(); return redirect("/")
@app.get("/admin/token")
def admin_token():
    if not session.get("admin_token"): return jsonify(error="No autorizado"),401
    return jsonify(token=session["admin_token"])

@app.post("/api/auth/login")
def customer_login():
    d=request.get_json() or {}
    with db_conn() as c: row=c.execute("SELECT id,username,password_hash,role,credits,active FROM users WHERE username=?",(d.get("username",""),)).fetchone()
    if not row or row[3]!="customer" or not row[5] or not pw_ok(d.get("password",""),row[2]): return jsonify(error="Usuario o contraseña incorrectos"),401
    return jsonify(token=token_for({"id":row[0],"role":row[3]}),user={"id":row[0],"username":row[1],"credits":row[4]})
@app.post("/api/auth/register")
def customer_register():
    d=request.get_json() or {}; u=str(d.get("username","")).strip(); p=str(d.get("password",""))
    if len(u)<3 or len(u)>32 or len(p)<8: return jsonify(error="Usuario mínimo 3 caracteres y contraseña mínimo 8"),400
    try:
        with db_conn() as c:
            c.execute("INSERT INTO users(id,username,password_hash,role,credits,active,created_at) VALUES(?,?,?,?,?,?,?)",(uid(),u,pw_hash(p),"customer",0,1,now())); c.commit()
        return jsonify(message="Cuenta creada. Ya puedes iniciar sesión."),201
    except Exception: return jsonify(error="Ese usuario ya existe"),409

@app.get("/api/products")
def products():
    with db_conn() as c:
        rows=c.execute("SELECT id,name,description FROM products WHERE active=1 ORDER BY created_at DESC").fetchall()
        out=[]
        for r in rows:
            plans=c.execute("SELECT id,label,price_cents FROM plans WHERE product_id=? AND active=1 ORDER BY label",(r[0],)).fetchall()
            out.append({"id":r[0],"name":r[1],"description":r[2],"plans":[{"id":p[0],"label":p[1],"price":p[2]/100} for p in plans]})
    return jsonify(products=out)

@app.get("/api/me")
@auth("customer")
def me(): return jsonify(user=request.current_user)

@app.post("/api/purchase")
@auth("customer")
def purchase():
    d=request.get_json() or {}; plan_id=d.get("plan_id"); qty=max(1,min(10,int(d.get("quantity",1))))
    with db_conn() as c:
        plan=c.execute("SELECT p.id,p.product_id,p.label,p.price_cents,pr.name FROM plans p JOIN products pr ON pr.id=p.product_id WHERE p.id=? AND p.active=1 AND pr.active=1",(plan_id,)).fetchone()
        if not plan: return jsonify(error="Plan no disponible"),404
        available=c.execute("SELECT id,secret_value FROM key_inventory WHERE product_id=? AND (plan_id=? OR plan_id IS NULL) AND status='available' LIMIT ?",(plan[1],plan[0],qty)).fetchall()
        if len(available)<qty: return jsonify(error="Inventario insuficiente. Contacta al administrador."),409
        total=plan[3]*qty
        user=c.execute("SELECT credits FROM users WHERE id=? AND active=1",(request.current_user["id"],)).fetchone()
        if not user or user[0]<total: return jsonify(error="Créditos insuficientes"),402
        order_id=uid()
        c.execute("UPDATE users SET credits=credits-? WHERE id=?",(total, request.current_user["id"]))
        c.execute("INSERT INTO orders(id,user_id,product_id,plan_id,quantity,total_cents,status,created_at) VALUES(?,?,?,?,?,?,?,?)",(order_id,request.current_user["id"],plan[1],plan[0],qty,total,"completed",now()))
        c.execute("INSERT INTO credit_ledger(id,user_id,amount,reason,admin_id,created_at) VALUES(?,?,?,?,?,?)",(uid(),request.current_user["id"],-total,"Compra "+plan[4],None,now()))
        delivered=[]
        for key in available:
            c.execute("UPDATE key_inventory SET status='sold',sold_to=?,sold_at=? WHERE id=? AND status='available'",(request.current_user["id"],now(),key[0]))
            delivered.append(key[1])
        c.commit()
    return jsonify(order_id=order_id,keys=delivered,total=total/100)

@app.get("/api/orders")
@auth("customer")
def customer_orders():
    with db_conn() as c: rows=c.execute("SELECT o.id,p.name,pl.label,o.quantity,o.total_cents,o.status,o.created_at FROM orders o JOIN products p ON p.id=o.product_id JOIN plans pl ON pl.id=o.plan_id WHERE o.user_id=? ORDER BY o.created_at DESC LIMIT 100",(request.current_user["id"],)).fetchall()
    return jsonify(orders=[dict(zip(["id","product","plan","quantity","total","status","created_at"],r)) for r in rows])

@app.get("/api/keys")
@auth("customer")
def customer_keys():
    with db_conn() as c:
        rows=c.execute("SELECT k.id,p.name,k.secret_value,k.sold_at FROM key_inventory k JOIN products p ON p.id=k.product_id WHERE k.sold_to=? AND k.status='sold' ORDER BY k.sold_at DESC LIMIT 200",(request.current_user["id"],)).fetchall()
    return jsonify(keys=[dict(zip(["id","product","key","sold_at"],r)) for r in rows])

@app.get("/api/admin/overview")
@auth("admin")
def overview():
    with db_conn() as c:
        users=c.execute("SELECT COUNT(*) FROM users WHERE role='customer'").fetchone()[0]
        products_count=c.execute("SELECT COUNT(*) FROM products").fetchone()[0]
        sales=c.execute("SELECT COALESCE(SUM(total_cents),0) FROM orders WHERE status='completed'").fetchone()[0]
        orders=c.execute("SELECT COUNT(*) FROM orders").fetchone()[0]
    return jsonify(users=users,products=products_count,sales=sales/100,orders=orders)

@app.get("/api/admin/products")
@auth("admin")
def admin_products():
    with db_conn() as c:
        rows=c.execute("SELECT id,name,description,active FROM products ORDER BY created_at DESC").fetchall(); out=[]
        for r in rows:
            plans=c.execute("SELECT id,label,price_cents,active FROM plans WHERE product_id=?",(r[0],)).fetchall()
            out.append({"id":r[0],"name":r[1],"description":r[2],"active":bool(r[3]),"plans":[{"id":p[0],"label":p[1],"price":p[2]/100,"active":bool(p[3])} for p in plans]})
    return jsonify(products=out)
@app.post("/api/admin/products")
@auth("admin")
def create_product():
    d=request.get_json() or {}; name=str(d.get("name","")).strip()
    if not name: return jsonify(error="Nombre obligatorio"),400
    pid=uid()
    with db_conn() as c:
        c.execute("INSERT INTO products(id,name,description,active,created_at) VALUES(?,?,?,?,?)",(pid,name,str(d.get("description","")),1,now()))
        for p in d.get("plans",[]):
            price=int(round(float(p.get("price",0))*100))
            if price<0: return jsonify(error="Precio inválido"),400
            c.execute("INSERT INTO plans(id,product_id,label,price_cents,active) VALUES(?,?,?,?,1)",(uid(),pid,str(p.get("label","Plan")),price))
        c.commit()
    return jsonify(id=pid,message="Producto creado"),201
@app.patch("/api/admin/products/<pid>")
@auth("admin")
def update_product(pid):
    d=request.get_json() or {}
    with db_conn() as c:
        c.execute("UPDATE products SET name=?,description=?,active=? WHERE id=?",(str(d.get("name","")).strip(),str(d.get("description","")),1 if d.get("active") else 0,pid))
        c.commit()
    return jsonify(message="Producto actualizado")
@app.post("/api/admin/products/<pid>/plans")
@auth("admin")
def add_plan(pid):
    d=request.get_json() or {}; price=int(round(float(d.get("price",0))*100))
    with db_conn() as c:
        exists=c.execute("SELECT id FROM products WHERE id=?",(pid,)).fetchone()
        if not exists: return jsonify(error="Producto no encontrado"),404
        c.execute("INSERT INTO plans(id,product_id,label,price_cents,active) VALUES(?,?,?,?,1)",(uid(),pid,str(d.get("label","Duración")),price)); c.commit()
    return jsonify(message="Plan agregado"),201
@app.post("/api/admin/inventory")
@auth("admin")
def add_inventory():
    d=request.get_json() or {}; pid=d.get("product_id"); plan_id=d.get("plan_id") or None
    values=[x.strip() for x in str(d.get("keys","")).splitlines() if x.strip()]
    if not values: return jsonify(error="Pega al menos una clave"),400
    with db_conn() as c:
        for value in values: c.execute("INSERT INTO key_inventory(id,product_id,plan_id,secret_value,status,created_at) VALUES(?,?,?,?,?,?)",(uid(),pid,plan_id,value,"available",now()))
        c.commit()
    return jsonify(added=len(values)),201
@app.get("/api/admin/users")
@auth("admin")
def admin_users():
    with db_conn() as c: rows=c.execute("SELECT id,username,credits,active,created_at FROM users WHERE role='customer' ORDER BY created_at DESC LIMIT 500").fetchall()
    return jsonify(users=[dict(zip(["id","username","credits","active","created_at"],r)) for r in rows])
@app.post("/api/admin/users")
@auth("admin")
def create_user():
    d=request.get_json() or {}; u=str(d.get("username","")).strip(); p=str(d.get("password",""))
    if len(u)<3 or len(p)<8: return jsonify(error="Usuario mínimo 3 y contraseña mínimo 8"),400
    try:
        with db_conn() as c:
            c.execute("INSERT INTO users(id,username,password_hash,role,credits,active,created_at) VALUES(?,?,?,?,?,?,?)",(uid(),u,pw_hash(p),"customer",0,1,now())); c.commit()
        return jsonify(message="Usuario creado"),201
    except Exception: return jsonify(error="Usuario ya existe"),409
@app.post("/api/admin/users/<user_id>/credits")
@auth("admin")
def change_credits(user_id):
    d=request.get_json() or {}; amount=int(d.get("amount",0)); reason=str(d.get("reason","Ajuste administrativo"))[:160]
    if amount==0 or abs(amount)>10000000: return jsonify(error="Cantidad inválida"),400
    with db_conn() as c:
        user=c.execute("SELECT id,credits FROM users WHERE id=? AND role='customer'",(user_id,)).fetchone()
        if not user: return jsonify(error="Usuario no encontrado"),404
        if user[1]+amount<0: return jsonify(error="El saldo no puede quedar negativo"),400
        c.execute("UPDATE users SET credits=credits+? WHERE id=?",(amount,user_id))
        c.execute("INSERT INTO credit_ledger(id,user_id,amount,reason,admin_id,created_at) VALUES(?,?,?,?,?,?)",(uid(),user_id,amount,reason,request.current_user["id"],now()))
        c.commit()
    return jsonify(message="Saldo actualizado")
@app.get("/api/admin/orders")
@auth("admin")
def admin_orders():
    with db_conn() as c: rows=c.execute("SELECT o.id,u.username,p.name,pl.label,o.quantity,o.total_cents,o.status,o.created_at FROM orders o JOIN users u ON u.id=o.user_id JOIN products p ON p.id=o.product_id JOIN plans pl ON pl.id=o.plan_id ORDER BY o.created_at DESC LIMIT 300").fetchall()
    return jsonify(orders=[dict(zip(["id","username","product","plan","quantity","total","status","created_at"],r)) for r in rows])
@app.get("/api/admin/inventory")
@auth("admin")
def inventory():
    with db_conn() as c:
        rows=c.execute("SELECT p.name,COUNT(*) FROM key_inventory k JOIN products p ON p.id=k.product_id WHERE k.status='available' GROUP BY p.name").fetchall()
    return jsonify(stock=[{"product":r[0],"available":r[1]} for r in rows])

if __name__=="__main__": app.run(host="0.0.0.0",port=int(os.getenv("PORT",5000)),debug=False)
