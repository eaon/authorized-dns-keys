# authorized-dns-keys

Small helper tool primarily meant to be invoked by OpenSSH's
`AuthorizedKeysCommand` in environments that already use
[Hesiod](https://en.wikipedia.org/wiki/Hesiod_\(name_service\))

It queries, sorts, concatenates and eventually prints SSH public keys found in
DNS TXT records.

Records are expected to live in `$username.ssh$lhs$rhs` and look like this:

    user.ssh.ns.example.org. TXT "0" "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQCutHjcbooZDl+4jpsGMC7JewGXTgULjWuSMMzpM0hCKn4aIOaULkbDV020NiO+dfo0DTo2vXwZn6GqUu4xyZVk5dQa+yk6He3DAzgwsXxsLuwQYfGI0xVgGsaBFWPXqXjWIq6amKKG6o2Ll15HOw6Tj0MULGqQtC/j00VrKxNztNy2Lesa06KkKnFBFimA29ZhVlUjm8W/t7rwg0alulLnoOp"
                             TXT "1" "ch9qbE/3yO3KOdNqCdDwNoRImAQk6KRlpWSr9ZHB4YnjQNNZCJ+yjC/KdqQ1awdKWTOMz2jfbhd/WHeH7XRY4iU2ZatVj6ZAcaqKvkaG8mWDYq2RNf6k88FgLdM33 user@host"
                             TXT "2" "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIHz4HTq0S77shqWG1tfc8EHSSMg+unYB+uUZaKiUcq1N user@host"

Since DNS responses aren't going to arrive in order and TXT records are limited
to 255 characters in length, `authorized-dns-keys` will concatenate multiple
entries by using the priority field as a guide.

Requires a `/etc/hesiod.conf` configuration file.
