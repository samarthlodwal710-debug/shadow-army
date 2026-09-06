const crypto = require('crypto');

const URL = process.env.SUPABASE_URL;
const KEY = process.env.SUPABASE_SERVICE_ROLE_KEY;
const SECRET = process.env.SESSION_SECRET;

const roles = ['Member','VIP Member','OG Member','Moderator','GC Admin','Website Head'];
const admins = ['Moderator','GC Admin','Website Head'];

function json(status, body, headers={}) {
  return {
    statusCode: status,
    headers: {'Content-Type':'application/json', ...headers},
    body: JSON.stringify(body)
  };
}

function corsHeaders() {
  return {
    'Access-Control-Allow-Origin':'*',
    'Access-Control-Allow-Headers':'Content-Type',
    'Access-Control-Allow-Credentials':'true'
  };
}

function b64url(x) {
  return Buffer.from(x).toString('base64url');
}

function sign(payload) {
  const p = b64url(JSON.stringify(payload));
  const s = crypto.createHmac('sha256', SECRET).update(p).digest('base64url');
  return p + '.' + s;
}

function verify(token) {
  try {
    const [p,s] = token.split('.');
    const expected = crypto.createHmac('sha256', SECRET)
      .update(p)
      .digest('base64url');

    if (!crypto.timingSafeEqual(
      Buffer.from(s),
      Buffer.from(expected)
    )) return null;

    const data = JSON.parse(Buffer.from(p,'base64url'));

    if (!data.exp || data.exp < Date.now()) return null;

    return data;
  } catch {
    return null;
  }
}

function cookie(token,maxAge=60*60*24*30) {
  return `shadow_session=${token}; Max-Age=${maxAge}; Path=/; HttpOnly; Secure; SameSite=Lax`;
}

function clearCookie() {
  return 'shadow_session=; Max-Age=0; Path=/; HttpOnly; Secure; SameSite=Lax';
}

function cookies(event) {
  const raw = event.headers.cookie || '';

  return Object.fromEntries(
    raw.split(';')
      .map(x => x.trim().split('='))
      .filter(x => x.length === 2)
  );
}

async function sb(path, options={}) {
  if (!URL || !KEY) {
    throw new Error('Missing Supabase environment variables');
  }

  const r = await fetch(`${URL}/rest/v1/${path}`, {
    ...options,
    headers: {
      apikey: KEY,
      Authorization: `Bearer ${KEY}`,
      'Content-Type':'application/json',
      Prefer:'return=representation',
      ...(options.headers || {})
    }
  });

  const text = await r.text();

  let data;
  try {
    data = JSON.parse(text);
  } catch {
    data = text;
  }

  if (!r.ok) {
    throw new Error(
      typeof data === 'string'
        ? data
        : (data.message || data.hint || 'Supabase request failed')
    );
  }

  return data;
}

function hashPassword(password) {
  const salt = crypto.randomBytes(16).toString('hex');

  const hash = crypto.pbkdf2Sync(
    password,
    salt,
    210000,
    32,
    'sha256'
  ).toString('hex');

  return `pbkdf2_sha256$210000$${salt}$${hash}`;
}

function checkPassword(password,stored) {
  const [alg,it,salt,hash] = String(stored).split('$');

  if (alg !== 'pbkdf2_sha256') return false;

  const got = crypto.pbkdf2Sync(
    password,
    salt,
    Number(it),
    32,
    'sha256'
  ).toString('hex');

  return crypto.timingSafeEqual(
    Buffer.from(got,'hex'),
    Buffer.from(hash,'hex')
  );
}

async function current(event) {
  const c = cookies(event);
  const s = c.shadow_session;
  const p = s && verify(s);

  if (!p) return null;

  const rows = await sb(
    `profiles?id=eq.${encodeURIComponent(p.id)}&select=*`
  );

  return rows[0] || null;
}

function validUsername(x) {
  return /^[A-Za-z0-9_]{3,24}$/.test(x);
}

function safeProfile(p) {
  const {
    id,
    name,
    username,
    class:cls,
    age,
    city,
    hobby,
    bio,
    profile_picture,
    role,
    created_at
  } = p;

  return {
    id,
    name,
    username,
    class:cls,
    age,
    city,
    hobby,
    bio,
    profile_picture,
    role,
    created_at
  };
}

exports.handler = async(event) => {

  const h = corsHeaders();

  if (event.httpMethod === 'OPTIONS') {
    return {
      statusCode:204,
      headers:h,
      body:''
    };
  }

  try {

    const body = event.body
      ? JSON.parse(event.body)
      : {};

    const action = body.action;

    /* REGISTER */

    if (action === 'register') {

      const name = String(body.name || '').trim();

      const username = String(body.username || '')
        .trim()
        .toLowerCase();

      const password = String(body.password || '');

      if (
        !name ||
        !validUsername(username) ||
        password.length < 8
      ) {
        return json(
          400,
          {
            error:'Name, a valid username and an 8+ character password are required.'
          },
          h
        );
      }

      if (
        password !== String(body.confirmPassword || '')
      ) {
        return json(
          400,
          {error:'Passwords do not match.'},
          h
        );
      }

      const existing = await sb(
        `auth_accounts?username=eq.${encodeURIComponent(username)}&select=id`
      );

      if (existing.length) {
        return json(
          409,
          {error:'Username already exists.'},
          h
        );
      }

      const profileRows = await sb(
        'profiles',
        {
          method:'POST',
          body:JSON.stringify({
            name,
            username,
            class:String(body.class || ''),
            age:body.age ? Number(body.age) : null,
            city:String(body.city || ''),
            hobby:String(body.hobby || ''),
            bio:String(body.bio || ''),
            profile_picture:String(body.profile_picture || ''),
            role:'Member'
          })
        }
      );

      const profile = profileRows[0];

      await sb(
        'auth_accounts',
        {
          method:'POST',
          body:JSON.stringify({
            profile_id:profile.id,
            username,
            password_hash:hashPassword(password)
          })
        }
      );

      const token = sign({
        id:profile.id,
        exp:Date.now() + 30*24*60*60*1000
      });

      return json(
        200,
        {profile:safeProfile(profile)},
        {
          ...h,
          'Set-Cookie':cookie(token)
        }
      );
    }

    /* LOGIN */

    if (action === 'login') {

      const username = String(body.username || '')
        .trim()
        .toLowerCase();

      const password = String(body.password || '');

      const rows = await sb(
        `auth_accounts?username=eq.${encodeURIComponent(username)}&select=profile_id,password_hash`
      );

      if (
        !rows[0] ||
        !checkPassword(password,rows[0].password_hash)
      ) {
        return json(
          401,
          {error:'Wrong username or password.'},
          h
        );
      }

      const profiles = await sb(
        `profiles?id=eq.${encodeURIComponent(rows[0].profile_id)}&select=*`
      );

      if (!profiles[0]) {
        return json(
          401,
          {error:'Account profile not found.'},
          h
        );
      }

      const token = sign({
        id:profiles[0].id,
        exp:Date.now() + 30*24*60*60*1000
      });

      return json(
        200,
        {profile:safeProfile(profiles[0])},
        {
          ...h,
          'Set-Cookie':cookie(token)
        }
      );
    }

    /* LOGOUT */

    if (action === 'logout') {
      return json(
        200,
        {ok:true},
        {
          ...h,
          'Set-Cookie':clearCookie()
        }
      );
    }

    /* CURRENT USER */

    if (action === 'me') {

      const u = await current(event);

      return u
        ? json(
            200,
            {profile:safeProfile(u)},
            h
          )
        : json(
            401,
            {error:'Not logged in.'},
            h
          );
    }

    /* AUTH REQUIRED */

    const u = await current(event);

    if (!u) {
      return json(
        401,
        {error:'Login required.'},
        h
      );
    }

    /* MEMBERS */

    if (action === 'members') {

      const rows = await sb(
        'profiles?select=id,name,username,class,age,city,hobby,bio,profile_picture,role,created_at&order=created_at.desc'
      );

      return json(
        200,
        {
          members:rows.map(safeProfile)
        },
        h
      );
    }

    /* RULES */

    if (action === 'rules') {

      return json(
        200,
        {
          rules:await sb(
            'rules?select=id,rule_text,created_at&order=id.asc'
          )
        },
        h
      );
    }

    /* ANNOUNCEMENTS */

    if (action === 'announcements') {

      return json(
        200,
        {
          announcements:await sb(
            'announcements?select=id,title,description,author_id,created_at&order=created_at.desc'
          )
        },
        h
      );
    }

    /* PROFILE UPDATE */

    if (action === 'profile_update') {

      const patch = {};

      for (
        const k of [
          'name',
          'class',
          'age',
          'city',
          'hobby',
          'bio',
          'profile_picture'
        ]
      ) {
        if (body[k] !== undefined) {
          patch[k] = body[k];
        }
      }

      const rows = await sb(
        `profiles?id=eq.${encodeURIComponent(u.id)}`,
        {
          method:'PATCH',
          body:JSON.stringify(patch)
        }
      );

      return json(
        200,
        {
          profile:safeProfile(rows[0])
        },
        h
      );
    }

    /* ADMIN */

    if (!admins.includes(u.role)) {
      return json(
        403,
        {error:'Admin permission required.'},
        h
      );
    }

    /* ADD RULE */

    if (action === 'add_rule') {

      if (!body.rule) {
        return json(
          400,
          {error:'Rule required.'},
          h
        );
      }

      return json(
        200,
        {
          rule:(await sb(
            'rules',
            {
              method:'POST',
              body:JSON.stringify({
                rule_text:String(body.rule).trim()
              })
            }
          ))[0]
        },
        h
      );
    }

    /* ADD ANNOUNCEMENT */

    if (action === 'add_announcement') {

      if (!body.title || !body.description) {
        return json(
          400,
          {error:'Title and description required.'},
          h
        );
      }

      return json(
        200,
        {
          announcement:(await sb(
            'announcements',
            {
              method:'POST',
              body:JSON.stringify({
                title:String(body.title).trim(),
                description:String(body.description).trim(),
                author_id:u.id
              })
            }
          ))[0]
        },
        h
      );
    }

    /* CHANGE ROLE */

    if (action === 'change_role') {

      if (u.role !== 'Website Head') {
        return json(
          403,
          {error:'Only Website Head can change roles.'},
          h
        );
      }

      const target = await sb(
        `profiles?username=eq.${encodeURIComponent(String(body.username || '').toLowerCase())}&select=*`
      );

      const newRole = String(body.role || '');

      if (
        !target[0] ||
        !roles.includes(newRole) ||
        newRole === 'Website Head'
      ) {
        return json(
          400,
          {error:'Invalid target or role.'},
          h
        );
      }

      const rows = await sb(
        `profiles?id=eq.${encodeURIComponent(target[0].id)}`,
        {
          method:'PATCH',
          body:JSON.stringify({
            role:newRole
          })
        }
      );

      return json(
        200,
        {
          profile:safeProfile(rows[0])
        },
        h
      );
    }

    /* STATS */

    if (action === 'stats') {

      const [
        members,
        rules,
        anns
      ] = await Promise.all([
        sb('profiles?select=role'),
        sb('rules?select=id'),
        sb('announcements?select=id')
      ]);

      return json(
        200,
        {
          members:members.length,
          admins:members.filter(
            x => admins.includes(x.role)
          ).length,
          vip:members.filter(
            x => x.role === 'VIP Member'
          ).length,
          og:members.filter(
            x => x.role === 'OG Member'
          ).length,
          rules:rules.length,
          announcements:anns.length
        },
        h
      );
    }

    return json(
      400,
      {error:'Unknown action.'},
      h
    );

  } catch(e) {

    console.error(e);

    return json(
      500,
      {error:'Server error. Check Netlify function logs.'},
      corsHeaders()
    );
  }
};
