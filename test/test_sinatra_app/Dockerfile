FROM ruby:2.4

#RUN apt-get update -qq && apt-get install -y build-essential

WORKDIR /app
COPY app/Gemfile /app/
RUN bundle install

RUN useradd --create-home --system --shell=/bin/false app

ADD app /app

## Ensure the coverage directory is present and writable
#RUN mkdir coverage; chown health:health coverage

RUN bundle exec rubocop

USER app
EXPOSE 4567
CMD bundle exec ruby test_app.rb