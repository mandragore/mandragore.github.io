---
layout: default
title: CTF
nav_order: 2
---

# Derniers articles, writeups choisis, davantage sur mon gist.

{% assign category_posts = site.categories['CTF'] %}

{% if category_posts %}
  <ul>
    {% for post in category_posts %}
      <li>
        <a href="{{ post.url | relative_url }}">{{ post.title }}</a>
        <span class="text-small text-grey-dk-000"> — {{ post.date | date: "%d/%m/%Y" }}</span>
      </li>
    {% endfor %}
  </ul>
{% else %}
  <p>Aucun article trouvé dans cette catégorie.</p>
{% endif %}
