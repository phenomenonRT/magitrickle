<p align="center">
  <img src="https://gitlab.com/magitrickle/magitrickle/-/raw/develop/img/logo256.png" alt="MagiTrickle logo"/>
</p>

MagiTrickle
=======

## Назначение

MagiTrickle (произносится как *Мэджитрикл*) – утилита для точечной маршрутизации сетевого трафика по заданным доменным именам. Представляет собой установочный пакет, устанавливаемый в дополнение к операционной системе маршрутизатора.

<p align="center">
  <img src="https://gitlab.com/magitrickle/magitrickle/-/raw/develop/img/main_screenshot.png" alt="MagiTrickle Screenshot"/>
</p>

Принцип работы основан на подмене основного DNS-сервера через промежуточный компонент без его отключения. Это позволяет перехватывать входящие DNS-запросы, кешировать ответы и сопоставлять IP-адреса с доменными именами. Благодаря этому становится возможной маршрутизация трафика без необходимости очистки DNS-кэша на стороне клиентов. Очистка кэша требуется только при запуске или перезапуске сервиса MagiTrickle, поскольку в этот момент кэш ещё не прогрет, и маршрутизация невозможна до первого запроса к нужному домену.

## Резервный интернет-канал

Для группы или подписки можно указать основной интерфейс и упорядоченный список резервных интерфейсов.

### Keenetic

Создайте на роутере политику доступа в интернет и задайте в ней приоритет подключений. Затем выберите эту политику в списке интерфейсов MagiTrickle. Переключением между подключениями управляет сам Keenetic: при отказе текущего подключения он использует следующее доступное подключение из политики.

### OpenWrt и другие системы с Linux

Выберите основной интерфейс, затем добавьте резервные в нужном порядке. MagiTrickle следит за событиями интерфейса через netlink: при отключении интерфейса его маршрут убирается сразу. Дополнительно сервис проверяет доступ в интернет TCP-подключением к публичным адресам IPv4 и IPv6 на порту 443, привязанным к каждому интерфейсу. После трёх неудачных проверок маршрут уступает настроенным резервам; после двух успешных проверок восстанавливает приоритет. Проверка запускается раз в пять секунд.

Для переключения интерфейс должен появляться в списке доступных интерфейсов MagiTrickle и иметь настроенный default route. Проверка подтверждает TCP-доступность публичных адресов на порту 443; если сеть блокирует эти подключения, канал может считаться недоступным. MagiTrickle устанавливает отдельные маршруты для своих правил и не меняет настройки `mwan3` или UCI.

## Установка (Entware)

1. Добавление репозитория в пакетный менеджер:
```shell
wget -qO- http://bin.magitrickle.dev/packages/add_repo.sh | sh
```
2. Установка пакета:
```shell
opkg update && opkg install magitrickle
```
3. Запуск пакета:
```shell
/opt/etc/init.d/S99magitrickle start
```

Дальнейшее обновление можно осуществлять с помощью:
```shell
opkg update && opkg install magitrickle
/opt/etc/init.d/S99magitrickle restart
```

## Установка (OpenWrt >= 25.12.X)

1. Добавление репозитория в пакетный менеджер:
```shell
wget -qO- http://bin.magitrickle.dev/packages/add_repo.sh | sh
```
2. Установка пакета:
```shell
apk update && apk add magitrickle
```
3. Запуск пакета:
```shell
service magitrickle start
```

Дальнейшее обновление можно осуществлять с помощью:
```shell
apk update && apk add magitrickle
service magitrickle restart
```

## Установка (OpenWrt <= 24.10.X)

1. Добавление репозитория в пакетный менеджер:
```shell
wget -qO- http://bin.magitrickle.dev/packages/add_repo.sh | sh
```
2. Установка пакета:
```shell
opkg update && opkg install magitrickle
```
3. Запуск пакета:
```shell
service magitrickle start
```

Дальнейшее обновление можно осуществлять с помощью:
```shell
opkg update && opkg install magitrickle
service magitrickle restart
```

## Описание типов правил

### Namespace (Именное пространство)

Охватывает указанный домен и все его поддомены.

Например, при записи `example.com` будут обрабатываться:
```
✅ example.com
✅ sub.example.com
✅ sub.sub.example.com
❌ anotherexample.com
❌ example.net
```

### Wildcard (Подстановочный шаблон)

Шаблон с `*` и `?` — позволяет задавать гибкие условия:
- `*` — любое количество любых символов
- `?` — ровно один любой символ

Например, при записи `*example.com` будут обрабатываться:
```
✅ example.com
✅ sub.example.com
✅ sub.sub.example.com
✅ anotherexample.com
❌ example.net
```

### Domain (Точный домен)

Правило применяется только к строго указанному домену, без поддоменов.

Например, при записи `sub.example.com` будут обрабатываться:
```
❌ example.com
✅ sub.example.com
❌ sub.sub.example.com
❌ anotherexample.com
❌ example.net
```

### RegExp (Регулярное выражение)

Для опытных пользователей. Используется парсер [dlclark/regexp2](https://github.com/dlclark/regexp2).

Например, при записи `^[a-z]*example\.com$` будут обрабатываться:
```
✅ example.com
❌ sub.example.com
❌ sub.sub.example.com
✅ anotherexample.com
❌ example.net
```

## Поддержка

* [Официальный сайт](https://magitrickle.dev)
* [Форум на Keenetic Community](https://forum.keenetic.ru/topic/20125-magitrickle)
* [Канал Telegram](https://t.me/MagiTrickle)
* [Чат Telegram](https://t.me/MagiTrickleChat)
* [Финансовая поддержка](https://boosty.to/magitrickle)
