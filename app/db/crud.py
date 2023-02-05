from typing import Union

from app.db.models import JWT, Admin, Proxy, ProxyInbound, System, User
from app.models.admin import AdminCreate, AdminModify
from app.models.user import UserCreate, UserModify, UserStatus
from sqlalchemy.orm import Session


def get_or_create_inbound(db: Session, inbound_tag: str):
    inbound = db.query(ProxyInbound).filter(ProxyInbound.tag == inbound_tag).first()
    if not inbound:
        inbound = ProxyInbound(tag=inbound_tag)
        db.add(inbound)
        db.commit()
        db.refresh(inbound)
    return inbound


def get_user(db: Session, username: str):
    return db.query(User).filter(User.username == username).first()


def get_user_by_id(db: Session, user_id: int):
    return db.query(User).filter(User.id == user_id).first()


def get_users(db: Session,
              offset: int = None,
              limit: int = None,
              username: str = None,
              status: Union[UserStatus, list] = None,
              admin: Admin = None):
    query = db.query(User)
    if admin:
        query = query.filter(User.admin == admin)
    if offset:
        query = query.offset(offset)
    if limit:
        query = query.limit(limit)
    if username:
        query = query.filter(User.username.ilike(f'{username}%'))
    if status:
        if isinstance(status, list):
            query = query.filter(User.status.in_(status))
        else:
            query = query.filter(User.status == status)
    return query.all()


def get_users_count(db: Session, status: UserStatus = None):
    query = db.query(User.id)
    if status:
        query = query.filter(User.status == status)
    return query.count()


def create_user(db: Session, user: UserCreate, admin: Admin = None):
    excluded_inbounds_tags = user.get_excluded_inbounds()
    proxies = []
    for ptype, settings in user.proxies.items():
        excluded_inbounds = [
            get_or_create_inbound(db, tag) for tag in excluded_inbounds_tags[ptype]
        ]
        proxies.append(
            Proxy(type=ptype.value,
                  settings=settings.dict(no_obj=True),
                  excluded_inbounds=excluded_inbounds)
        )

    dbuser = User(
        username=user.username,
        proxies=proxies,
        data_limit=(user.data_limit or None),
        expire=(user.expire or None),
        admin=admin
    )
    db.add(dbuser)
    db.commit()
    db.refresh(dbuser)
    return dbuser


def remove_user(db: Session, dbuser: User):
    db.delete(dbuser)
    db.commit()
    return dbuser


def update_user(db: Session, dbuser: User, modify: UserModify):
    if modify.proxies:
        for proxy_type, settings in modify.proxies.items():
            dbproxy = db.query(Proxy) \
                .where(Proxy.user == dbuser, Proxy.type == proxy_type) \
                .first()
            if dbproxy:
                dbproxy.settings = settings.dict(no_obj=True)
            else:
                dbuser.proxies.append(Proxy(type=proxy_type, settings=settings.dict(no_obj=True)))
        for proxy in dbuser.proxies:
            if proxy.type not in modify.proxies:
                db.delete(proxy)

    if modify.inbounds:
        excluded_inbounds_tags = modify.get_excluded_inbounds()
        for proxy_type, tags in excluded_inbounds_tags.items():
            dbproxy = db.query(Proxy) \
                .where(Proxy.user == dbuser, Proxy.type == proxy_type) \
                .first()
            if dbproxy:
                dbproxy.excluded_inbounds = [get_or_create_inbound(db, tag) for tag in tags]

    if modify.data_limit is not None:
        dbuser.data_limit = (modify.data_limit or None)

    if modify.expire is not None:
        dbuser.expire = (modify.expire or None)

    db.commit()
    db.refresh(dbuser)
    return dbuser


def update_user_status(db: Session, dbuser: User, status: UserStatus):
    dbuser.status = status
    db.commit()
    db.refresh(dbuser)
    return dbuser


def get_system_usage(db: Session):
    return db.query(System).first()


def get_jwt_secret_key(db: Session):
    return db.query(JWT).first().secret_key


def get_admin(db: Session, username: str):
    return db.query(Admin).filter(Admin.username == username).first()


def create_admin(db: Session, admin: AdminCreate):
    dbadmin = Admin(
        username=admin.username,
        hashed_password=admin.hashed_password
    )
    db.add(dbadmin)
    db.commit()
    db.refresh(dbadmin)
    return dbadmin


def update_admin(db: Session, dbadmin: Admin, modified_admin: AdminModify):
    dbadmin.hashed_password = modified_admin.hashed_password
    db.commit()
    db.refresh(dbadmin)
    return dbadmin


def remove_admin(db: Session, dbadmin: Admin):
    db.delete(dbadmin)
    db.commit()
    return dbadmin


def get_admins(db: Session,
               offset: int = None,
               limit: int = None,
               username: str = None):
    query = db.query(Admin)
    if offset:
        query = query.offset(offset)
    if limit:
        query = query.limit(limit)
    if username:
        query = query.filter(User.username.ilike(f'{username}%'))
    return query.all()
