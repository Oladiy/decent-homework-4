# **Project description**

Программа VNS (Vasya Name Service) реализует name-сервис для создания профилей пользователей в IPFS. Это сервис, в котором “именем” является комбинация “user_name + user_public_key”, а ответом на запрос по имени является IPFS-линк на данные о пользователе. При этом, user, владеющий секретным ключом от public key может обновить IPFS ссылку на свой профиль, отправив в сервис запрос на обновление, подписав новую ссылку своим секретным ключом. 

Ключи должны быть ECDSA.
pubkey и signature - в формате hex.

Возможно хранение данных о нескольких пользователях.
При get-запросе из IPFS считывается информация о пользователе.

# **Run**

**Mode set**

`go run vns-server.go --request-type=name-record-set --uid=vasya:1213...afde --ipfs-link=Qm23492323….afde --sig=fa23213...32321`

**Mode get**

`go run vns-server.go --request-type=name-record-get --uid=vasya:1213...afde`

# **Example**

Пусть есть пользователь vasya с публичным ключом ECDSA 

`vasya:304e301006072a8648ce3d020106052b81040021033a000489968a323fea63c6aaf830ab7d133c409799b9b2d8ede09978f93ad90a3a9cd0cd8ece420892fac825abe265c915e760e17873a93bc5dde0`

vasya загрузил в IPFS данные о себе и получил IPFS-link

`QmYzbC3q6zcHkxohBfm5xuPbgMuHQzYHxBvHrp18RjXZFh`

Он подписывает этот link и загружает на сервис

`go run vns-server.go --request-type=name-record-set --uid=vasya:304e301006072a8648ce3d020106052b81040021033a000489968a323fea63c6aaf830ab7d133c409799b9b2d8ede09978f93ad90a3a9cd0cd8ece420892fac825abe265c915e760e17873a93bc5dde0 --ipfs-link=QmYzbC3q6zcHkxohBfm5xuPbgMuHQzYHxBvHrp18RjXZFh --sig=303d021d00dfe2e9c3a35d2a00a922ea406d6781165fd7cfd9944662039d74546c021c7b43f9b36a932a5e4444c78ecc971b769292ca62c068ecb980f2d1c7` 

Результат:

`result: ok (signature correct)`

Теперь любой обратившийся к сервису, запросив “vasya:public-key” должен получить ipfs линк последней версии + информацию об этом пользователе

`go run vns-server.go --request-type=name-record-get --uid=vasya:304e301006072a8648ce3d020106052b81040021033a000489968a323fea63c6aaf830ab7d133c409799b9b2d8ede09978f93ad90a3a9cd0cd8ece420892fac825abe265c915e760e17873a93bc5dde0`

Результат:

`link: QmYzbC3q6zcHkxohBfm5xuPbgMuHQzYHxBvHrp18RjXZFh
 data(optional, from IPFS node):
 Name: Vasiliy Ivanovich Chapaev
 Birthdate: 01-01-1970`

