FROM ruby:2.5.9

RUN useradd --create-home testsuite

COPY Gemfile /app/Gemfile
RUN cd /app; bundle install

COPY ./ /app
WORKDIR /app

RUN bundle exec rubocop

RUN mkdir -p /test_files/httpd /test_files/keys && \
   bundle exec ruby bin/generate_test_files.rb

USER testsuite
VOLUME ["/test_files"]
