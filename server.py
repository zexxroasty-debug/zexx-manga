from http.server import ThreadingHTTPServer, SimpleHTTPRequestHandler
import os
from pathlib import Path
from urllib.parse import parse_qs
import sqlite3, hashlib, secrets, time, re, json, uuid

DB="zexx.db"
SESSIONS={}
VIEW_TIMES={}

def db():
    c=sqlite3.connect(DB)
    c.execute("CREATE TABLE IF NOT EXISTS users(id INTEGER PRIMARY KEY,username TEXT UNIQUE NOT NULL,password_hash TEXT NOT NULL)")
    c.execute("CREATE TABLE IF NOT EXISTS stats(id INTEGER PRIMARY KEY CHECK(id=1),views INTEGER NOT NULL DEFAULT 0)")
    c.execute("CREATE TABLE IF NOT EXISTS comments(id INTEGER PRIMARY KEY AUTOINCREMENT,username TEXT NOT NULL,comment TEXT NOT NULL,created_at TEXT NOT NULL)")
    c.execute("INSERT OR IGNORE INTO stats(id,views) VALUES(1,0)")
    c.commit()
    return c

def hash_password(password,salt=None):
    salt=salt or secrets.token_hex(16)
    h=hashlib.pbkdf2_hmac("sha256",password.encode(),salt.encode(),200000)
    return salt+"$"+h.hex()

def check_password(password,stored):
    try:
        salt,old=stored.split("$",1)
        new=hash_password(password,salt).split("$",1)[1]
        return secrets.compare_digest(new,old)
    except:
        return False

def user(h):
    cookie=h.headers.get("Cookie","")
    for x in cookie.split(";"):
        x=x.strip()
        if x.startswith("zexx_session="):
            return SESSIONS.get(x.split("=",1)[1])
    return None

def is_owner(h):
    return user(h)=="Zexxofficial"

def send_json(h,obj,status=200):
    body=json.dumps(obj).encode()
    h.send_response(status)
    h.send_header("Content-Type","application/json")
    h.send_header("Cache-Control","no-store")
    h.send_header("Content-Length",str(len(body)))
    h.end_headers()
    h.wfile.write(body)

def redirect(h,path):
    h.send_response(302)
    h.send_header("Location",path)
    h.end_headers()

class Handler(SimpleHTTPRequestHandler):
    def do_GET(self):
        path=self.path.split("?",1)[0]

        if path=="/owner/" or path=="/owner/index.html":
            if not is_owner(self):
                redirect(self,"/login.html")
                return
            self.path="/owner/index.html"

        if path in ["/login.html","/signup.html","/"]:
            return super().do_GET()

        if path.startswith("/anime/my-anime.html") or path.startswith("/anime/episode-") or path.startswith("/anime/videos/"):
            if not user(self):
                redirect(self,"/login.html")
                return

        if path=="/api/owner/anime":
            if not is_owner(self):
                send_json(self,{"error":"owner access required"},403)
                return
            c=db()
            rows=c.execute("SELECT id,name,cover,created_at FROM anime ORDER BY id DESC").fetchall()
            c.close()
            send_json(self,{"anime":[{"id":r[0],"name":r[1],"cover":r[2],"created_at":r[3]} for r in rows]})
            return

        if path=="/api/me":
            u=user(self)
            if not u:
                send_json(self,{"error":"login required"},401)
            else:
                send_json(self,{"username":u})
            return

        if path=="/api/comments":
            c=db()
            rows=c.execute("SELECT id,username,comment,created_at FROM comments ORDER BY id DESC").fetchall()
            c.close()
            send_json(self,{"comments":[{"id":r[0],"username":r[1],"comment":r[2],"created_at":r[3]} for r in rows]})
            return

        if path=="/api/views":
            u=user(self)
            if not u:
                send_json(self,{"error":"login required"},401)
                return
            now=time.time()
            VIEW_TIMES={k:v for k,v in VIEW_TIMES.items() if now-v<30}
            c=db()
            views=c.execute("SELECT views FROM stats WHERE id=1").fetchone()[0]
            c.close()
            send_json(self,{"views":views,"watching":len(VIEW_TIMES)})
            return

        if path=="/api/episodes":
            c=db()
            rows=c.execute("""
                SELECT e.id,e.anime_id,e.episode_number,e.title,
                       e.video_file,e.created_at,e.category,a.name
                FROM episodes e
                JOIN anime a ON a.id=e.anime_id
                ORDER BY e.id DESC
            """).fetchall()
            c.close()

            send_json(self,{
                "episodes":[
                    {
                        "id":r[0],
                        "anime_id":r[1],
                        "episode_number":r[2],
                        "title":r[3],
                        "video_file":r[4],
                        "created_at":r[5],
                        "category":r[6],
                        "anime_name":r[7]
                    }
                    for r in rows
                ]
            })
            return

        super().do_GET()

    def do_POST(self):
        path=self.path.split("?",1)[0]

        # ZEXX_STREAM_UPLOAD_START
        if path=="/api/owner/video/upload":
            if not is_owner(self):
                send_json(self,{"error":"owner access required"},403)
                return

            title=self.headers.get("X-Video-Title","").strip()
            category=self.headers.get("X-Video-Category","Anime").strip()
            anime_id=self.headers.get("X-Anime-ID","").strip()
            filename=self.headers.get("X-Video-Filename","").strip()

            if not title:
                send_json(self,{"error":"Video title is required"},400)
                return

            if len(title)>150:
                send_json(self,{"error":"Video title must be 150 characters or less"},400)
                return

            if category not in ("Anime","Popular","Latest"):
                send_json(self,{"error":"Invalid category"},400)
                return

            if not anime_id.isdigit():
                send_json(self,{"error":"Valid anime ID is required"},400)
                return

            if not filename:
                send_json(self,{"error":"Video filename is required"},400)
                return

            ext=Path(filename).suffix.lower()
            allowed={".mp4",".webm",".mov",".m4v",".mkv"}
            if ext not in allowed:
                send_json(self,{"error":"Unsupported video format"},400)
                return

            c=db()
            anime=c.execute("SELECT id FROM anime WHERE id=?",(int(anime_id),)).fetchone()

            if not anime:
                c.close()
                send_json(self,{"error":"Anime not found"},404)
                return

            episode_row=c.execute(
                "SELECT COALESCE(MAX(episode_number),0)+1 FROM episodes WHERE anime_id=?",
                (int(anime_id),)
            ).fetchone()
            episode_number=episode_row[0]

            safe_name=uuid.uuid4().hex+ext
            video_dir=Path("anime/videos")
            video_dir.mkdir(parents=True,exist_ok=True)
            video_path=video_dir/safe_name

            try:
                remaining=int(self.headers.get("Content-Length","0"))
                if remaining<=0:
                    raise ValueError("Empty upload")

                with open(video_path,"wb") as out:
                    while remaining>0:
                        chunk=self.rfile.read(min(1024*1024,remaining))
                        if not chunk:
                            raise ValueError("Upload ended unexpectedly")
                        out.write(chunk)
                        remaining-=len(chunk)

                c.execute(
                    "INSERT INTO episodes(anime_id,episode_number,title,video_file,created_at,category) VALUES(?,?,?,?,datetime('now'),?)",
                    (int(anime_id),episode_number,title,"videos/"+safe_name,category)
                )
                c.commit()
                episode_id=c.execute("SELECT last_insert_rowid()").fetchone()[0]
                c.close()

                send_json(self,{
                    "ok":True,
                    "id":episode_id,
                    "anime_id":int(anime_id),
                    "episode_number":episode_number,
                    "title":title,
                    "category":category,
                    "video_file":"videos/"+safe_name
                })
                return

            except Exception as e:
                try:
                    if video_path.exists():
                        video_path.unlink()
                except:
                    pass
                c.close()
                send_json(self,{"error":"Upload failed: "+str(e)},500)
                return
        # ZEXX_STREAM_UPLOAD_END

        length=int(self.headers.get("Content-Length",0))
        data=parse_qs(self.rfile.read(length).decode())

        if path=="/api/signup":
            username=data.get("username",[""])[0].strip()
            password=data.get("password",[""])[0]
            confirm=data.get("confirm",[""])[0]

            if not re.fullmatch(r"[A-Za-z0-9_]{3,20}",username):
                send_json(self,{"error":"Username must be 3-20 letters, numbers or _"},400)
                return
            if len(password)<6:
                send_json(self,{"error":"Password must be at least 6 characters"},400)
                return
            if password!=confirm:
                send_json(self,{"error":"Passwords do not match"},400)
                return

            try:
                c=db()
                c.execute("INSERT INTO users(username,password_hash) VALUES(?,?)",(username,hash_password(password)))
                c.commit()
                c.close()
            except sqlite3.IntegrityError:
                send_json(self,{"error":"Username is already taken"},409)
                return

            redirect(self,"/login.html")
            return

        if path=="/api/login":
            username=data.get("username",[""])[0].strip()
            password=data.get("password",[""])[0]

            c=db()
            row=c.execute("SELECT password_hash FROM users WHERE username=?",(username,)).fetchone()
            c.close()

            if not row or not check_password(password,row[0]):
                send_json(self,{"error":"Invalid username or password"},401)
                return

            token=secrets.token_urlsafe(32)
            SESSIONS[token]=username

            self.send_response(302)
            self.send_header("Location","/anime/")
            self.send_header("Set-Cookie","zexx_session="+token+"; HttpOnly; SameSite=Lax; Path=/")
            self.end_headers()
            return

        if path=="/api/logout":
            cookie=self.headers.get("Cookie","")
            for x in cookie.split(";"):
                x=x.strip()
                if x.startswith("zexx_session="):
                    SESSIONS.pop(x.split("=",1)[1],None)
            self.send_response(302)
            self.send_header("Location","/")
            self.send_header("Set-Cookie","zexx_session=; Max-Age=0; HttpOnly; SameSite=Lax; Path=/")
            self.end_headers()
            return

        if path=="/api/comments":
            u=user(self)
            if not u:
                send_json(self,{"error":"login required"},401)
                return
            comment=data.get("comment",[""])[0].strip()
            if not comment:
                send_json(self,{"error":"Comment cannot be empty"},400)
                return
            if len(comment)>1500:
                send_json(self,{"error":"Comment is limited to 1500 characters"},400)
                return
            c=db()
            count=c.execute("SELECT COUNT(*) FROM comments").fetchone()[0]
            if count>=50:
                c.close()
                send_json(self,{"error":"Maximum 50 comments reached"},400)
                return
            c.execute("INSERT INTO comments(username,comment,created_at) VALUES(?,?,datetime(now))",(u,comment))
            c.commit()
            c.close()
            send_json(self,{"ok":True})
            return

        if path=="/api/owner/anime/create":
            if not is_owner(self):
                send_json(self,{"error":"owner access required"},403)
                return
            name=data.get("name",[""])[0].strip()
            if not name:
                send_json(self,{"error":"Anime name is required"},400)
                return
            if len(name)>100:
                send_json(self,{"error":"Anime name must be 100 characters or less"},400)
                return
            c=db()
            c.execute("INSERT INTO anime(name,cover,created_at) VALUES(?,?,datetime(now))",(name,"")) 
            c.commit()
            anime_id=c.execute("SELECT last_insert_rowid()").fetchone()[0]
            c.close()
            send_json(self,{"ok":True,"id":anime_id,"name":name})
            return

        if path=="/api/view":
            u=user(self)
            if not u:
                send_json(self,{"error":"login required"},401)
                return

            now=time.time()
            if u in VIEW_TIMES and now-VIEW_TIMES[u]<10:
                send_json(self,{"ok":True,"limited":True})
                return

            VIEW_TIMES[u]=now
            c=db()
            c.execute("UPDATE stats SET views=views+1 WHERE id=1")
            c.commit()
            c.close()
            send_json(self,{"ok":True})
            return

        send_json(self,{"error":"not found"},404)

db()
server=ThreadingHTTPServer(("0.0.0.0",int(os.environ.get("PORT","8083"))),Handler)
print("ZEXX TV SECURE SERVER running on port 8083")
server.serve_forever()
